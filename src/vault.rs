//! One handle's view of a vault, answering each [`Call`] with one library call.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use libvault::generate::{self, PasswordRules, SecretSize};
use libvault::item::{self, Kind, Meta, Secret};
use libvault::{Client, Connect, Cost, Error, ErrorCode, ImportFile, Join, PendingJoin, Recovery, RecoveryDraft, Result, Setup, Totp};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::call::Call;

/// What a file holds, as counts. Row numbers point at what could not be read, never at its content.
#[derive(Serialize)]
struct ImportPreview {
    logins: usize,
    logins_with_codes: usize,
    variables: usize,
    unreadable: Vec<usize>,
}

/// A device joining, from listening to confirming.
enum Joining {
    Listening(Box<Join>),
    Matched(Box<PendingJoin>),
}

/// One handle's view of a vault.
pub struct Vault {
    home: PathBuf,
    client: Option<Client>,
    setup: Option<Setup>,
    joining: Option<Joining>,
    recovery: Option<Recovery>,
    rotation: Option<RecoveryDraft>,
    import: Option<ImportFile>,
    /// Kept for reconnecting, so a handle limited to one space can never lose that limit.
    session: Option<Zeroizing<String>>,
    /// A vault with no secure hardware takes this in place of a touch, on each request.
    passphrase: Option<Zeroizing<String>>,
    /// The app group's folder, for a sandboxed handle that reaches the broker only there.
    shared: Option<PathBuf>,
}

/// Reserved up front, so a reply holding a secret never leaves a copy in a reallocated buffer.
const REPLY_CAPACITY: usize = 64 * 1024;

fn json(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let mut reply = Zeroizing::new(Vec::with_capacity(REPLY_CAPACITY));
    serde_json::to_writer(&mut *reply, value).map_err(|_| Error::Usage("that reply could not be encoded"))?;
    Ok(reply)
}

fn done() -> Result<Zeroizing<Vec<u8>>> {
    json(&true)
}

/// In tests, where `lvd` is not beside the program and setup must be quick.
fn test_daemon() -> Option<PathBuf> {
    if cfg!(feature = "test-hooks") { std::env::var_os("LV_DAEMON").map(PathBuf::from) } else { None }
}

fn test_cost() -> Cost {
    if cfg!(feature = "test-hooks") && std::env::var_os("LV_FAST_KDF").is_some() { Cost::FAST } else { Cost::STRONG }
}

impl Vault {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            client: None,
            setup: None,
            joining: None,
            recovery: None,
            rotation: None,
            import: None,
            session: None,
            passphrase: None,
            shared: None,
        }
    }

    fn connect(&mut self) -> Result<&mut Client> {
        let daemon = test_daemon();
        let session = self.session.as_ref().map(|session| session.as_str());
        let passphrase = self.passphrase.as_ref().map(|passphrase| passphrase.as_str());
        let options = Connect { passphrase, session, daemon: daemon.as_deref() };
        let client = match &self.shared {
            Some(folder) => Client::connect_shared(folder, options)?,
            None => Client::connect(&self.home, options)?,
        };
        Ok(self.client.insert(client))
    }

    fn client(&mut self) -> Result<&mut Client> {
        if self.client.is_some() {
            return self.client.as_mut().ok_or(Error::Usage("connect first"));
        }
        self.connect()
    }

    fn setup(&self) -> Result<&Setup> {
        self.setup.as_ref().ok_or(Error::Usage("begin setup first"))
    }

    fn recovery(&self) -> Result<&Recovery> {
        self.recovery.as_ref().ok_or(Error::Usage("open a copy first"))
    }

    fn rotation(&self) -> Result<&RecoveryDraft> {
        self.rotation.as_ref().ok_or(Error::Usage("begin replacing the recovery key first"))
    }

    fn import_preview(file: &ImportFile) -> ImportPreview {
        let logins = file.items.iter().filter(|(_, secret)| matches!(secret, Secret::Login { .. }));
        ImportPreview {
            logins: logins.clone().count(),
            logins_with_codes: logins.filter(|(_, secret)| matches!(secret, Secret::Login { totp: Some(_), .. })).count(),
            variables: file.items.iter().filter(|(_, secret)| matches!(secret, Secret::Env { .. })).count(),
            unreadable: file.unreadable.clone(),
        }
    }

    fn wait_for_device(&mut self, seconds: u64) -> Result<Zeroizing<Vec<u8>>> {
        let Some(Joining::Listening(join)) = self.joining.take() else {
            return Err(Error::Usage("begin joining first"));
        };
        let pending = join.wait(Duration::from_secs(seconds))?;
        let reply = json(pending.words());
        self.joining = Some(Joining::Matched(Box::new(pending)));
        reply
    }

    pub fn run(&mut self, call: Call) -> Result<Zeroizing<Vec<u8>>> {
        let result = self.dispatch(call);
        // A broker that stopped is started again by the next call.
        if matches!(&result, Err(error) if error.code() == ErrorCode::Error && matches!(error, Error::BrokerUnavailable(_) | Error::Io(_))) {
            self.client = None;
        }
        result
    }

    /// New items only: replacing one is a separate, deliberate call.
    fn add(&mut self, space: Option<&str>, meta: Meta, secret: Secret) -> Result<Zeroizing<Vec<u8>>> {
        self.client()?.add(space, meta, secret, false)?;
        done()
    }

    #[allow(clippy::too_many_lines, reason = "one arm per call, which reads better than one function per arm")]
    fn dispatch(&mut self, call: Call) -> Result<Zeroizing<Vec<u8>>> {
        match call {
            Call::Exists => json(&libvault::exists(&self.home)),
            Call::NeedsPassphrase => json(&libvault::needs_passphrase(&self.home)?),
            Call::HasSecureHardware => json(&libvault::has_secure_hardware()),
            Call::DeviceName => json(&libvault::device_name()),
            Call::SetupBegin { passphrase } => {
                let setup = match passphrase {
                    Some(passphrase) => Setup::with_passphrase(&passphrase, test_cost())?,
                    None => Setup::with_hardware()?,
                };
                self.setup = Some(setup);
                done()
            }
            Call::SetupWords => json(&*self.setup()?.recovery().words()),
            Call::SetupPositions => json(&self.setup()?.recovery().confirmation_positions()),
            Call::SetupCheckWord { position, answer } => json(&self.setup()?.recovery().check_word(position, &answer)),
            Call::SetupFinish { device_name } => {
                let setup = self.setup.take().ok_or(Error::Usage("begin setup first"))?;
                setup.finish(&self.home, &device_name)?;
                done()
            }
            Call::JoinBegin { passphrase, device_name } => {
                let join = match passphrase {
                    Some(passphrase) => Join::with_passphrase(&passphrase, test_cost(), &device_name)?,
                    None => Join::with_hardware(&device_name)?,
                };
                let port = join.port()?;
                self.joining = Some(Joining::Listening(Box::new(join)));
                json(&port)
            }
            Call::JoinWait { seconds } => self.wait_for_device(seconds),
            Call::JoinConfirm => {
                let Some(Joining::Matched(pending)) = self.joining.take() else {
                    return Err(Error::Usage("wait for a device first"));
                };
                pending.confirm(&self.home)?;
                done()
            }
            Call::RecoverOpen { source, words, as_it_stood } => {
                let recovery = if as_it_stood { Recovery::open_as_it_stood(&source, &words)? } else { Recovery::open(&source, &words)? };
                self.recovery = Some(recovery);
                done()
            }
            Call::RecoverHistories => json(&self.recovery()?.histories()),
            Call::RecoverChoose { index } => {
                self.recovery.as_mut().ok_or(Error::Usage("open a copy first"))?.choose_history(index)?;
                done()
            }
            Call::RecoverProblems => json(&self.recovery()?.problems()),
            Call::RecoverFinish { passphrase, device_name } => {
                let recovery = self.recovery.take().ok_or(Error::Usage("open a copy first"))?;
                match passphrase {
                    Some(passphrase) => recovery.finish_with_passphrase(&passphrase, test_cost(), &self.home, &device_name)?,
                    None => recovery.finish_with_hardware(&self.home, &device_name)?,
                }
                done()
            }
            Call::ConnectShared { folder, passphrase, session } => {
                self.shared = Some(folder);
                self.session = session;
                self.passphrase = passphrase;
                self.connect()?;
                done()
            }
            Call::Connect { passphrase, session } => {
                self.session = session;
                self.passphrase = passphrase;
                self.connect()?;
                done()
            }
            Call::Status => json(&self.client()?.status()?),
            Call::Grant { space, agent, seconds } => {
                let (token, id) = self.client()?.grant(space.as_deref(), &agent, Duration::from_secs(seconds))?;
                json(&serde_json::json!({ "token": token, "id": id }))
            }
            Call::Grants => json(&self.client()?.grants()?),
            Call::EndGrant { id } => {
                self.client()?.end_grant(&id)?;
                done()
            }
            Call::Stop => {
                self.client()?.stop()?;
                self.client = None;
                done()
            }
            Call::Unlock => {
                self.client()?.unlock()?;
                done()
            }
            Call::Lock => {
                self.client()?.lock()?;
                done()
            }
            Call::Spaces => json(&self.client()?.spaces()?),
            Call::CreateSpace { name } => {
                self.client()?.create_space(&name)?;
                done()
            }
            Call::Items { space } => json(&self.client()?.items(space.as_deref())?),
            Call::Item { space, name } => json(&self.client()?.item(space.as_deref(), &name)?),
            Call::AddEnv { space, name, value } => self.add(space.as_deref(), Meta::env(name), Secret::Env { value: value.to_string() }),
            Call::AddLogin { space, name, username, urls, password, totp } => {
                let mut meta = Meta::login(name);
                meta.username = username;
                if let Some(urls) = urls {
                    meta.urls = urls;
                }
                let password = match password {
                    Some(password) => password.to_string(),
                    None => generate::password(PasswordRules::default())?.to_string(),
                };
                if let Some(totp) = &totp {
                    Totp::parse(totp)?;
                }
                self.add(space.as_deref(), meta, Secret::Login { password, totp: totp.map(|totp| totp.to_string()) })
            }
            Call::AddNote { space, name, body } => self.add(space.as_deref(), Meta::new(Kind::Note, name), Secret::Note { body: body.to_string() }),
            Call::AddWifi { space, name, password } => {
                self.add(space.as_deref(), Meta::new(Kind::Wifi, name), Secret::Wifi { password: password.to_string() })
            }
            Call::AddSsh { space, name, private_key } => {
                self.add(space.as_deref(), Meta::new(Kind::Ssh, name), Secret::Ssh { private_key: private_key.to_string() })
            }
            Call::AddCard { space, name, number, expiry, cvc, holder } => {
                let (meta, secret) = item::card(name, &number, expiry, cvc.to_string(), holder)?;
                self.add(space.as_deref(), meta, secret)
            }
            Call::AddProfile { space, name, profile } => self.add(space.as_deref(), Meta::new(Kind::Profile, name), Secret::Profile(profile)),
            Call::Link { space, name, to } => {
                self.client()?.link(space.as_deref(), &name, &to)?;
                done()
            }
            Call::Edit { space, name, meta, secret } => {
                self.client()?.edit(space.as_deref(), &name, meta, secret)?;
                done()
            }
            Call::Remove { space, name } => {
                self.client()?.remove(space.as_deref(), &name)?;
                done()
            }
            Call::Undo => json(&self.client()?.undo()?),
            Call::History { space, name } => json(&self.client()?.history(space.as_deref(), &name)?),
            Call::Restore { space, name, version } => {
                self.client()?.restore(space.as_deref(), &name, version)?;
                done()
            }
            Call::Reveal { space, name } => json(&self.client()?.reveal(space.as_deref(), &name)?),
            Call::Code { space, name } => json(&self.client()?.code(space.as_deref(), &name)?),
            Call::RemoveCode { space, name } => {
                self.client()?.remove_code(space.as_deref(), &name)?;
                done()
            }
            Call::Expiring => json(&self.client()?.expiring()?),
            Call::AutofillIdentities => json(&self.client()?.autofill_identities()?),
            Call::PasskeyOptions { origin, allow } => json(&self.client()?.passkey_options(&origin, allow.unwrap_or_default())?),
            Call::CreatePasskey(request) => json(&self.client()?.create_passkey(request)?),
            Call::SignPasskey { space, name, origin, client_data_hash } => {
                json(&self.client()?.sign_passkey(&space, &name, &origin, &client_data_hash)?)
            }
            Call::LockSettings => json(&self.client()?.lock_settings()?),
            Call::SetLockSettings { settings } => {
                self.client()?.set_lock_settings(settings)?;
                done()
            }
            Call::FillOptions { origin } => json(&self.client()?.fill_options(&origin)?),
            Call::Fill { space, name, origin } => json(&self.client()?.fill(&space, &name, &origin)?),
            Call::Icon { space, url } => json(&self.client()?.icon(space.as_deref(), &url)?),
            Call::SaveIcon { space, url, png } => {
                let png = base64::engine::general_purpose::STANDARD.decode(png).map_err(|_| Error::Invalid("an icon must be PNG bytes in base64"))?;
                self.client()?.save_icon(space.as_deref(), &url, &png)?;
                done()
            }
            Call::GeneratePassword { length, symbols } => {
                let default = PasswordRules::default();
                json(&*generate::password(PasswordRules { length: length.unwrap_or(default.length), symbols: symbols.unwrap_or(default.symbols) })?)
            }
            Call::GenerateSecret { bytes: 32 } => json(&*generate::secret(SecretSize::Bytes32)),
            Call::GenerateSecret { bytes: 64 } => json(&*generate::secret(SecretSize::Bytes64)),
            Call::GenerateSecret { .. } => Err(Error::Invalid("a secret is 32 or 64 bytes")),
            Call::Allow { space, name, host } => {
                self.client()?.allow(space.as_deref(), &name, &host)?;
                done()
            }
            Call::ImportRead { path } => {
                let file = ImportFile::read(&path)?;
                let reply = json(&Self::import_preview(&file));
                self.import = Some(file);
                reply
            }
            Call::ImportFinish { space } => {
                let file = self.import.take().ok_or(Error::Usage("read a file first"))?;
                json(&self.client()?.import(space.as_deref(), file.items)?)
            }
            Call::Devices => json(&self.client()?.devices()?),
            Call::PairBegin { address } => json(&self.client()?.begin_pairing(address.as_deref())?),
            Call::PairConfirm { recovery } => json(&self.client()?.confirm_pairing(recovery.as_ref().map(|words| words.as_str()))?),
            Call::RemoveDevice { name, recovery } => json(&self.client()?.remove_device(&name, recovery.as_ref().map(|words| words.as_str()))?),
            Call::RotationBegin => {
                self.rotation = Some(RecoveryDraft::new());
                done()
            }
            Call::RotationWords => json(&*self.rotation()?.words()),
            Call::RotationPositions => json(&self.rotation()?.confirmation_positions()),
            Call::RotationCheckWord { position, answer } => json(&self.rotation()?.check_word(position, &answer)),
            Call::RotationFinish { recovery } => {
                let draft = self.rotation.take().ok_or(Error::Usage("begin replacing the recovery key first"))?;
                self.client()?.rotate_recovery(&draft, recovery.as_ref().map(|words| words.as_str()))?;
                done()
            }
            Call::ExportArchive { path } => {
                self.client()?.export_archive(&path)?;
                done()
            }
            Call::ExportPlaintext { path, recovery } => {
                self.client()?.export_plaintext(&path, recovery.as_ref().map(|words| words.as_str()))?;
                done()
            }
            Call::IcloudDrive => json(&libvault::icloud_drive()),
            Call::AddBackup { folder } => {
                self.client()?.add_backup(&folder)?;
                done()
            }
            Call::RemoveBackup { folder } => {
                self.client()?.remove_backup(&folder)?;
                done()
            }
            Call::VerifyBackup { folder } => json(&self.client()?.verify_backup(&folder)?),
            Call::SyncNow => json(&self.client()?.sync_now()?),
            Call::ResolveConflict { words } => json(&self.client()?.resolve_conflict(&words)?),
            Call::Wipe { device_name } => {
                self.client()?.wipe(&device_name)?;
                self.client = None;
                done()
            }
            Call::Audit => json(&self.client()?.audit()?),
        }
    }
}
