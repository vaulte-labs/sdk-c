//! Every call an SDK can make. A call carries its `"method"` and its fields as JSON, such as
//! `{"method":"reveal","name":"OPENAI_API_KEY","space":"Work"}`.

use std::path::PathBuf;

use libvault::item::{Meta, Secret};
use libvault::{Client, Connect, Cost, Error, ErrorCode, Result, Setup};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[allow(clippy::large_enum_variant, reason = "a call lives for one dispatch, so its size costs nothing")]
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Call {
    /// Whether a vault exists here, which needs no broker.
    Exists,
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
    /// Connecting happens by itself. This is for a software vault's passphrase or an agent's session.
    Connect {
        passphrase: Option<Zeroizing<String>>,
        session: Option<Zeroizing<String>>,
    },
    Status,
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
    Add {
        space: Option<String>,
        meta: Meta,
        secret: Secret,
        #[serde(default)]
        replace: bool,
    },
    Remove {
        space: Option<String>,
        name: String,
    },
    Undo,
    Reveal {
        space: Option<String>,
        name: String,
    },
    Devices,
    Audit,
}

/// One handle's view of a vault.
pub struct Vault {
    home: PathBuf,
    client: Option<Client>,
    setup: Option<Setup>,
}

fn json(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(value).map(Zeroizing::new).map_err(|_| Error::Usage("that reply could not be encoded"))
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
        Self { home, client: None, setup: None }
    }

    fn connect(&mut self, passphrase: Option<&str>, session: Option<&str>) -> Result<&mut Client> {
        let daemon = test_daemon();
        let client = Client::connect(&self.home, Connect { passphrase, session, daemon: daemon.as_deref() })?;
        Ok(self.client.insert(client))
    }

    fn client(&mut self) -> Result<&mut Client> {
        if self.client.is_some() {
            return self.client.as_mut().ok_or(Error::Usage("connect first"));
        }
        self.connect(None, None)
    }

    fn setup(&self) -> Result<&Setup> {
        self.setup.as_ref().ok_or(Error::Usage("begin setup first"))
    }

    pub fn run(&mut self, call: Call) -> Result<Zeroizing<Vec<u8>>> {
        let result = self.dispatch(call);
        // A broker that stopped is started again by the next call.
        if matches!(&result, Err(error) if error.code() == ErrorCode::Error && matches!(error, Error::BrokerUnavailable(_) | Error::Io(_))) {
            self.client = None;
        }
        result
    }

    fn dispatch(&mut self, call: Call) -> Result<Zeroizing<Vec<u8>>> {
        match call {
            Call::Exists => json(&libvault::exists(&self.home)),
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
            Call::Connect { passphrase, session } => {
                self.connect(passphrase.as_ref().map(|value| value.as_str()), session.as_ref().map(|value| value.as_str()))?;
                done()
            }
            Call::Status => json(&self.client()?.status()?),
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
            Call::Add { space, meta, secret, replace } => {
                self.client()?.add(space.as_deref(), meta, secret, replace)?;
                done()
            }
            Call::Remove { space, name } => {
                self.client()?.remove(space.as_deref(), &name)?;
                done()
            }
            Call::Undo => json(&self.client()?.undo()?),
            Call::Reveal { space, name } => json(&self.client()?.reveal(space.as_deref(), &name)?),
            Call::Devices => json(&self.client()?.devices()?),
            Call::Audit => json(&self.client()?.audit()?),
        }
    }
}
