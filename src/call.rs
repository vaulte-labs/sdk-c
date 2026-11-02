//! Every call an SDK can make. A call carries its `"method"` and its fields as JSON, such as
//! `{"method":"reveal","name":"OPENAI_API_KEY","space":"Work"}`.

use std::path::PathBuf;
use std::time::Duration;

use libvault::item::{self, Kind, Meta, Secret};
use libvault::{Client, Connect, Cost, Error, ErrorCode, ImportFile, Join, PendingJoin, Recovery, RecoveryDraft, Result, Setup, Totp};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Call {
    /// Whether a vault exists here, which needs no broker.
    Exists,
    /// Whether this vault asks for a passphrase in place of a touch.
    NeedsPassphrase,
    HasSecureHardware,
    DeviceName,
    /// Starts a new vault. `passphrase` is for devices without secure hardware.
    SetupBegin {
        passphrase: Option<Zeroizing<String>>,
    },
    SetupWords,
    SetupPositions,
    SetupCheckWord {
        position: usize,
        answer: String,
    },
    SetupFinish {
        device_name: String,
    },
    /// Listens for an enrolled device, returning the port one can reach it on when it cannot find
    /// this one by itself. Nothing is written until the person confirms.
    JoinBegin {
        passphrase: Option<Zeroizing<String>>,
        device_name: String,
    },
    /// Blocks until a device connects, and returns the words both screens show.
    JoinWait {
        seconds: u64,
    },
    /// The words match. Blocks until the other device approves, then creates the vault here.
    JoinConfirm,
    /// Opens a backup folder or archive with the 24 words. Nothing is written.
    RecoverOpen {
        source: PathBuf,
        words: Zeroizing<String>,
        /// For words that were replaced: the vault as it stood until then.
        as_it_stood: bool,
    },
    /// What is wrong with the open copy, for a person to weigh before trusting it.
    RecoverProblems,
    RecoverFinish {
        passphrase: Option<Zeroizing<String>>,
        device_name: String,
    },
    /// Connecting happens by itself. This is for a software vault's passphrase or an agent's session.
    Connect {
        passphrase: Option<Zeroizing<String>>,
        session: Option<Zeroizing<String>>,
    },
    Status,
    /// A session for an agent, limited to one space. Hand its `token` to `connect`.
    Grant {
        space: Option<String>,
        agent: String,
        seconds: u64,
    },
    Grants,
    EndGrant {
        id: String,
    },
    /// Stops the broker, which locks the vault.
    Stop,
    Unlock,
    Lock,
    Spaces,
    CreateSpace {
        name: String,
    },
    Items {
        space: Option<String>,
    },
    Item {
        space: Option<String>,
        name: String,
    },
    /// Allowed hosts for a well-known name are filled in by the library.
    AddEnv {
        space: Option<String>,
        name: String,
        value: Zeroizing<String>,
    },
    /// With no `password`, the library generates one. `totp` is a two-factor secret as a site
    /// shows it.
    AddLogin {
        space: Option<String>,
        name: String,
        username: Option<String>,
        urls: Option<Vec<String>>,
        password: Option<Zeroizing<String>>,
        totp: Option<Zeroizing<String>>,
    },
    AddNote {
        space: Option<String>,
        name: String,
        body: Zeroizing<String>,
    },
    AddSsh {
        space: Option<String>,
        name: String,
        private_key: Zeroizing<String>,
    },
    /// The library checks the number and keeps only a safe hint in view.
    AddCard {
        space: Option<String>,
        name: String,
        number: Zeroizing<String>,
        expiry: String,
        cvc: Zeroizing<String>,
        holder: String,
    },
    /// Replaces an item that exists, after a touch. The old version stays in its history.
    Replace {
        space: Option<String>,
        meta: Meta,
        secret: Secret,
    },
    Remove {
        space: Option<String>,
        name: String,
    },
    Undo,
    History {
        space: Option<String>,
        name: String,
    },
    Restore {
        space: Option<String>,
        name: String,
        version: usize,
    },
    Reveal {
        space: Option<String>,
        name: String,
    },
    GeneratePassword,
    /// The current code for a saved two-factor secret.
    TotpCode {
        secret: Zeroizing<String>,
    },
    Allow {
        space: Option<String>,
        name: String,
        host: String,
    },
    /// Reads a file into memory and says what is in it. Nothing touches the vault.
    ImportRead {
        path: PathBuf,
    },
    /// Writes what `import_read` found, as one batch.
    ImportFinish {
        space: Option<String>,
    },
    Devices,
    /// Finds a joining device, at `address` or on this network, and returns the words to compare.
    PairBegin {
        address: Option<String>,
    },
    /// The words match. Returns the new device's name.
    PairConfirm {
        recovery: Option<Zeroizing<String>>,
    },
    /// Returns the names of everything that device could read.
    RemoveDevice {
        name: String,
        recovery: Option<Zeroizing<String>>,
    },
    /// Starts replacing the recovery key. Confirm with the `rotation_` calls, then `rotation_finish`.
    RotationBegin,
    RotationWords,
    RotationPositions,
    RotationCheckWord {
        position: usize,
        answer: String,
    },
    RotationFinish {
        recovery: Option<Zeroizing<String>>,
    },
    ExportArchive {
        path: PathBuf,
    },
    ExportPlaintext {
        path: PathBuf,
        recovery: Option<Zeroizing<String>>,
    },
    /// iCloud Drive's folder, when it is in use.
    IcloudDrive,
    AddBackup {
        folder: PathBuf,
    },
    RemoveBackup {
        folder: PathBuf,
    },
    VerifyBackup {
        folder: PathBuf,
    },
    SyncNow,
    ResolveConflict {
        words: Zeroizing<String>,
    },
    Wipe {
        device_name: String,
    },
    Audit,
}

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
        Self { home, client: None, setup: None, joining: None, recovery: None, rotation: None, import: None, session: None, passphrase: None }
    }

    fn connect(&mut self) -> Result<&mut Client> {
        let daemon = test_daemon();
        let session = self.session.as_ref().map(|session| session.as_str());
        let passphrase = self.passphrase.as_ref().map(|passphrase| passphrase.as_str());
        let client = Client::connect(&self.home, Connect { passphrase, session, daemon: daemon.as_deref() })?;
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
            Call::RecoverProblems => json(&self.recovery.as_ref().ok_or(Error::Usage("open a copy first"))?.problems()),
            Call::RecoverFinish { passphrase, device_name } => {
                let recovery = self.recovery.take().ok_or(Error::Usage("open a copy first"))?;
                match passphrase {
                    Some(passphrase) => recovery.finish_with_passphrase(&passphrase, test_cost(), &self.home, &device_name)?,
                    None => recovery.finish_with_hardware(&self.home, &device_name)?,
                }
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
                meta.urls.extend(urls.into_iter().flatten());
                let password = password.map_or_else(item::generate_password, |password| password.to_string());
                if let Some(totp) = &totp {
                    Totp::parse(totp)?;
                }
                self.add(space.as_deref(), meta, Secret::Login { password, totp: totp.map(|totp| totp.to_string()) })
            }
            Call::AddNote { space, name, body } => self.add(space.as_deref(), Meta::new(Kind::Note, name), Secret::Note { body: body.to_string() }),
            Call::AddSsh { space, name, private_key } => {
                self.add(space.as_deref(), Meta::new(Kind::Ssh, name), Secret::Ssh { private_key: private_key.to_string() })
            }
            Call::AddCard { space, name, number, expiry, cvc, holder } => {
                let (meta, secret) = item::card(name, &number, expiry, cvc.to_string(), holder)?;
                self.add(space.as_deref(), meta, secret)
            }
            Call::Replace { space, meta, secret } => {
                // A card's hint comes from its number, so a new number has to make a new hint.
                if let Secret::Card { number, expiry, cvc, holder } = &secret {
                    let (meta, secret) = item::card(meta.name, number, expiry.clone(), cvc.clone(), holder.clone())?;
                    self.client()?.add(space.as_deref(), meta, secret, true)?;
                } else {
                    self.client()?.add(space.as_deref(), meta, secret, true)?;
                }
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
            Call::GeneratePassword => json(&item::generate_password()),
            Call::TotpCode { secret } => json(&Totp::parse(&secret)?.now()),
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
