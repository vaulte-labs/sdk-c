//! Every call an SDK can make. A call carries its `"method"` and its fields as JSON, such as
//! `{"method":"reveal","name":"OPENAI_API_KEY","space":"Work"}`. A call that names no result
//! replies `{"result":true}` when it is done. A `space` left out is the first space, Personal.

use std::path::PathBuf;

use libvault::item::{Meta, Profile, Secret};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Call {
    /// Whether a vault exists here, which needs no broker.
    Exists,
    /// Whether this vault asks for a passphrase in place of a touch.
    NeedsPassphrase,
    /// Whether this device has secure hardware for the vault's keys, as a boolean.
    HasSecureHardware,
    /// The name this device goes by, as a string.
    DeviceName,
    /// Starts a new vault. `passphrase` is for devices without secure hardware.
    SetupBegin { passphrase: Option<Zeroizing<String>> },
    /// The new recovery key's 24 words, as one string, to show once.
    SetupWords,
    /// Which words (0-based) to ask the person to type back, as an array of numbers.
    SetupPositions,
    /// Whether `answer` is the word at `position`, as a boolean.
    SetupCheckWord { position: usize, answer: String },
    /// Writes the vault, after a touch.
    SetupFinish { device_name: String },
    /// Listens for an enrolled device, returning the port one can reach it on when it cannot find
    /// this one by itself. Nothing is written until the person confirms.
    JoinBegin { passphrase: Option<Zeroizing<String>>, device_name: String },
    /// Blocks until a device connects, and returns the words both screens show.
    JoinWait { seconds: u64 },
    /// The words match. Blocks until the other device approves, then creates the vault here.
    JoinConfirm,
    /// Opens a backup folder or archive with the 24 words. Nothing is written.
    RecoverOpen {
        source: PathBuf,
        words: Zeroizing<String>,
        /// For words that were replaced: the vault as it stood until then.
        as_it_stood: bool,
    },
    /// The histories in the open copy that no signature separates, each with its devices and newest
    /// items. With two or more, the person picks theirs with `recover_choose` before finishing.
    RecoverHistories,
    /// Picks one of `recover_histories` by its index.
    RecoverChoose { index: usize },
    /// What is wrong with the open copy, for a person to weigh before trusting it.
    RecoverProblems,
    /// Writes the recovered vault on this device.
    RecoverFinish { passphrase: Option<Zeroizing<String>>, device_name: String },
    /// Connecting happens by itself. This is for a software vault's passphrase or an agent's session.
    Connect { passphrase: Option<Zeroizing<String>>, session: Option<Zeroizing<String>> },
    /// For the vault's own sandboxed code, such as an autofill extension: reaches a running broker
    /// through the app group's `folder`, and never the vault's folder or a broker of its own.
    ConnectShared { folder: PathBuf, passphrase: Option<Zeroizing<String>>, session: Option<Zeroizing<String>> },
    /// The vault's state: whether it is unlocked, its devices, backups and problems.
    Status,
    /// A session for an agent, limited to one space, as `{"token","id","space","seconds"}`. Hand
    /// its `token` to `connect`. It lasts from a second to 24 hours; anything else is refused.
    Grant {
        space: Option<String>,
        agent: String,
        seconds: u64,
        /// Why the agent wants it, shown in the prompt.
        reason: Option<String>,
    },
    /// The grants still running, each with its `id`, agent, space and seconds left.
    Grants,
    /// Ends a grant at once.
    EndGrant { id: String },
    /// Stops the broker, which locks the vault.
    Stop,
    /// Unlocks the vault, after a touch.
    Unlock,
    /// Locks the vault now, ending every session.
    Lock,
    /// The space names, as an array of strings.
    Spaces,
    /// Makes a new, empty space, named without the spaces around it. A name differing only by case
    /// from one in use is refused, and a removed space with this name comes back.
    CreateSpace { name: String },
    /// Renames a space after a touch, and returns its new name as kept. Its items and grants go
    /// with it. Personal keeps its name.
    RenameSpace { name: String, to: String },
    /// Removes an empty space after a touch. One holding anything is refused, saying how much it
    /// holds. `create_space` with its name brings it back with its history. Personal stays.
    RemoveSpace { name: String },
    /// The items in a space, without their secrets.
    Items { space: Option<String> },
    /// One item without its secret.
    Item { space: Option<String>, name: String },
    /// Allowed hosts for a well-known name are filled in by the library.
    AddEnv { space: Option<String>, name: String, value: Zeroizing<String> },
    /// With no `password`, the library generates one. `totp` is a two-factor secret as a site
    /// shows it. `urls` replace the site a dotted name suggests.
    AddLogin {
        space: Option<String>,
        name: String,
        username: Option<String>,
        urls: Option<Vec<String>>,
        password: Option<Zeroizing<String>>,
        totp: Option<Zeroizing<String>>,
    },
    /// Saves a note.
    AddNote { space: Option<String>, name: String, body: Zeroizing<String> },
    /// Saves an SSH private key.
    AddSsh { space: Option<String>, name: String, private_key: Zeroizing<String> },
    /// The network's name is the item's name.
    AddWifi { space: Option<String>, name: String, password: Zeroizing<String> },
    /// The library checks the number and keeps only a safe hint in view.
    AddCard { space: Option<String>, name: String, number: Zeroizing<String>, expiry: String, cvc: Zeroizing<String>, holder: String },
    /// A person's details for forms, any of which may be left out. A list shows only `name`.
    AddProfile { space: Option<String>, name: String, profile: Profile },
    /// Shows an item in the space `to` as well, after a touch. Later changes reach every copy.
    Link { space: Option<String>, name: String, to: String },
    /// Takes an item out of its space and into `to`, after a touch, as one change.
    Move { space: Option<String>, name: String, to: String },
    /// Changes what is shown about an item, and its secret only when one is given, after a touch.
    /// An edit that sends no setup key keeps a login's two-factor; `remove_code` takes it off in
    /// the same change, so one `undo` reverses the whole edit. The old version stays in its history.
    Edit {
        space: Option<String>,
        name: String,
        meta: Meta,
        secret: Option<Secret>,
        #[serde(default)]
        remove_code: bool,
    },
    /// Deletes an item, after a touch. `history` and `restore` bring it back.
    Remove { space: Option<String>, name: String },
    /// Removes several items as one change, so one `undo` brings them all back.
    RemoveAll { items: Vec<Named> },
    /// Reverses this device's last change not undone yet, after a touch. Each call goes one
    /// change further back. Returns the names of the items it changed back.
    Undo,
    /// An item's versions, oldest first, each with `at_ms`, `deleted`, its `name`, what it
    /// `changed` from the one before, whether it is `current`, whether a restore or an undo wrote
    /// it (`restored`), and whether it holds exactly what the item holds now (`identical`), so
    /// restoring it would change nothing. A version's index is what `restore` takes.
    History { space: Option<String>, name: String },
    /// Makes one of an item's versions current again, as a new change.
    Restore { space: Option<String>, name: String, version: usize },
    /// An item's secret, after a touch every time.
    Reveal { space: Option<String>, name: String },
    /// A login's current code and the seconds it has left, after a touch. The setup key never
    /// leaves the broker.
    Code { space: Option<String>, name: String },
    /// Every login's current code in `space`, or every space, after one touch, which the vault's
    /// own app does not need while the vault is open (`status.trusted`). One record per call, and
    /// for that app one per space each time the vault unlocks.
    Codes { space: Option<String> },
    /// Cards that run out soon, for a reminder. Never asks for a touch.
    Expiring,
    /// Each login's sites and username for the system's autofill to suggest, never a secret.
    AutofillIdentities,
    /// The passkeys that fit `origin`, or only those of `allow` (credential ids) when the site
    /// names its own. Never a prompt.
    PasskeyOptions { origin: String, allow: Option<Vec<Vec<u8>>> },
    /// Makes and saves a passkey for the site, after a touch: `{origin, rp_id, user_name,
    /// user_handle, exclude?, space?}`, with byte fields as arrays of numbers.
    CreatePasskey(libvault::PasskeyRequest),
    /// Signs a sign-in on `origin` with a saved passkey, after a touch. `client_data_hash` is the
    /// SHA-256 of the client data built for the page.
    SignPasskey { space: String, name: String, origin: String, client_data_hash: Vec<u8> },
    /// When this device's vault locks by itself: `{stay_unlocked, with_screen}`.
    LockSettings,
    /// Changes when this device's vault locks by itself, after a touch. `stay_unlocked` is
    /// `five_minutes`, `ten_minutes`, `one_hour`, `two_hours` or `never`.
    SetLockSettings { settings: libvault::LockSettings },
    /// What could fill at `origin`, which the system or browser reports, not the page.
    FillOptions { origin: String },
    /// What to put on the page at `origin`, after a touch naming the item and the site.
    Fill { space: String, name: String, origin: String },
    /// The icon saved for a site, as RGBA pixels decoded in safe code, or null.
    Icon { space: Option<String>, url: String },
    /// Saves a site's icon from PNG bytes in base64, made small first. The first icon saved stays.
    SaveIcon { space: Option<String>, url: String, png: String },
    /// The library's default when a field is left out.
    GeneratePassword { length: Option<usize>, symbols: Option<bool> },
    /// 32 or 64 random bytes, in hex.
    GenerateSecret { bytes: u16 },
    /// Lets an env var be sent to `host` through the proxy. Only env vars are sent anywhere.
    Allow { space: Option<String>, name: String, host: String },
    /// Reads a file into memory and says what is in it. Nothing touches the vault.
    ImportRead { path: PathBuf },
    /// Writes what `import_read` found, as one batch.
    ImportFinish { space: Option<String> },
    /// The devices that can open this vault.
    Devices,
    /// Finds a joining device, at `address` or on this network, and returns the words to compare.
    PairBegin { address: Option<String> },
    /// The words match. Returns the new device's name.
    PairConfirm { recovery: Option<Zeroizing<String>> },
    /// Returns the names of everything that device could read.
    RemoveDevice { name: String, recovery: Option<Zeroizing<String>> },
    /// Starts replacing the recovery key. Confirm with the `rotation_` calls, then `rotation_finish`.
    RotationBegin,
    /// The new recovery key's 24 words, as one string, to show once.
    RotationWords,
    /// Which words (0-based) to ask the person to type back.
    RotationPositions,
    /// Whether `answer` is the word at `position`, as a boolean.
    RotationCheckWord { position: usize, answer: String },
    /// Replaces the recovery key, after a touch. The old words stop opening anything new.
    RotationFinish { recovery: Option<Zeroizing<String>> },
    /// Writes an encrypted copy of the vault to `path`, which only the 24 words open.
    ExportArchive { path: PathBuf },
    /// Writes every secret in plaintext to `path`, after the 24 words. Only for leaving Vaulte.
    ExportPlaintext { path: PathBuf, recovery: Option<Zeroizing<String>> },
    /// iCloud Drive's folder, when it is in use.
    IcloudDrive,
    /// Keeps an encrypted copy of the vault in `folder`, updated as it changes.
    AddBackup { folder: PathBuf },
    /// Stops keeping a copy in `folder`. What is there stays.
    RemoveBackup { folder: PathBuf },
    /// Checks the copy in `folder` opens and is current, and reports what it found.
    VerifyBackup { folder: PathBuf },
    /// Reaches every other device now, and reports how many answered.
    SyncNow,
    /// Settles a conflict between devices in favour of the side these words belong to.
    ResolveConflict { words: Zeroizing<String> },
    /// Erases this vault from this device. Other devices and backups keep theirs.
    Wipe { device_name: String },
    /// Who used what: every recorded event, oldest first.
    Audit,
    /// The subscription account this device uses, as `{account, paid_until}`: `account` is null
    /// with none, and `paid_until` (seconds since 1970) is null when the account service could not
    /// be reached.
    RelayStatus,
    /// Starts the subscription, making an account on this device if it has none, and returns
    /// `{account, url}`: the number to keep, and Stripe's checkout page to open. `email` is for
    /// receipts. Devices with the account sync through the relay Vaulte hosts.
    RelaySubscribe { email: Option<String> },
    /// Uses an account the person already has, from another device, by its sixteen digits.
    RelayAccount { number: String },
    /// Stripe's page for this device's account, where its person cancels, changes their card or
    /// gets invoices, as a URL string.
    RelayBilling,
}

/// An item by its space and name.
#[derive(Deserialize)]
pub struct Named {
    pub space: Option<String>,
    pub name: String,
}
