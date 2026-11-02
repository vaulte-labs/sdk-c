//! Every call an SDK can make. A call carries its `"method"` and its fields as JSON, such as
//! `{"method":"reveal","name":"OPENAI_API_KEY","space":"Work"}`.

use std::path::PathBuf;

use libvault::item::{Meta, Secret};
use serde::Deserialize;
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
    /// The histories in the open copy that no signature separates, each with its devices and newest
    /// items. With two or more, the person picks theirs with `recover_choose` before finishing.
    RecoverHistories,
    RecoverChoose {
        index: usize,
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
    /// shows it. `urls` replace the site a dotted name suggests.
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
    /// The network's name is the item's name.
    AddWifi {
        space: Option<String>,
        name: String,
        password: Zeroizing<String>,
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
    /// Changes what is shown about an item, and its secret only when one is given, after a touch.
    /// The old version stays in its history.
    Edit {
        space: Option<String>,
        name: String,
        meta: Meta,
        secret: Option<Secret>,
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
    /// A login's current code and the seconds it has left, after a touch. The setup key never
    /// leaves the broker.
    Code {
        space: Option<String>,
        name: String,
    },
    /// Cards that run out soon, for a reminder. Never asks for a touch.
    Expiring,
    /// The icon saved for a site, as RGBA pixels decoded in safe code, or null.
    Icon {
        space: Option<String>,
        url: String,
    },
    /// Saves a site's icon from PNG bytes in base64, made small first. The first icon saved stays.
    SaveIcon {
        space: Option<String>,
        url: String,
        png: String,
    },
    /// The library's default when a field is left out.
    GeneratePassword {
        length: Option<usize>,
        symbols: Option<bool>,
    },
    /// 32 or 64 random bytes, in hex.
    GenerateSecret {
        bytes: u16,
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
