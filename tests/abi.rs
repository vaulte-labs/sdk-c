//! The ABI the way another language uses it: pointers in, JSON out, against a real broker.
#![cfg(feature = "test-hooks")]

use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde_json::{Value, json};
use vaulty::{LvHandle, lv_call, lv_close, lv_free_string, lv_open};

const PASSPHRASE: &str = "test passphrase";

/// Builds the broker these tests run against, so a stale one can never answer them.
fn use_test_broker() {
    static DAEMON: OnceLock<PathBuf> = OnceLock::new();
    let daemon = DAEMON.get_or_init(|| {
        let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../libvault");
        let status = Command::new("cargo").args(["build", "--bin", "lvd", "--features", "test-hooks"]).current_dir(&core).status().unwrap();
        assert!(status.success(), "lvd did not build");
        core.join("target/debug/lvd")
    });
    // SAFETY: every test sets the same two values before any thread reads them back.
    unsafe {
        std::env::set_var("LV_DAEMON", daemon);
        std::env::set_var("LV_FAST_KDF", "1");
    }
}

struct Handle(*mut LvHandle);

impl Handle {
    fn open(home: &Path) -> Self {
        use_test_broker();
        let home = CString::new(home.to_str().unwrap()).unwrap();
        // SAFETY: a valid string, and the handle is closed once by `Drop`.
        let handle = unsafe { lv_open(home.as_ptr()) };
        assert!(!handle.is_null());
        Self(handle)
    }

    fn raw(&self, call: &str) -> Value {
        let call = CString::new(call).unwrap();
        // SAFETY: a live handle and a valid string, and the reply is copied before it is freed.
        unsafe {
            let reply = lv_call(self.0, call.as_ptr());
            let value = serde_json::from_slice(CStr::from_ptr(reply).to_bytes()).unwrap();
            lv_free_string(reply);
            value
        }
    }

    fn call(&self, call: &Value) -> Value {
        let reply = self.raw(&call.to_string());
        assert!(reply.get("error").is_none(), "{call}: {reply}");
        reply["result"].clone()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: closed once, here.
        unsafe { lv_close(self.0) };
    }
}

fn new_vault(home: &Path) -> Handle {
    let vault = Handle::open(home);
    assert_eq!(vault.call(&json!({ "method": "exists" })), false);
    vault.call(&json!({ "method": "setup_begin", "passphrase": PASSPHRASE }));
    let words: Vec<String> = vault.call(&json!({ "method": "setup_words" })).as_str().unwrap().split(' ').map(str::to_owned).collect();
    assert_eq!(words.len(), 24);
    for position in vault.call(&json!({ "method": "setup_positions" })).as_array().unwrap() {
        let position = position.as_u64().unwrap();
        let word = &words[usize::try_from(position).unwrap()];
        assert_eq!(vault.call(&json!({ "method": "setup_check_word", "position": position, "answer": word })), true);
        assert_eq!(vault.call(&json!({ "method": "setup_check_word", "position": position, "answer": "notaword" })), false);
    }
    vault.call(&json!({ "method": "setup_finish", "device_name": "test mac" }));
    assert_eq!(vault.call(&json!({ "method": "exists" })), true);
    vault.call(&json!({ "method": "connect", "passphrase": PASSPHRASE }));
    vault
}

#[test]
fn a_vault_is_created_used_and_locked_through_the_abi() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);

    vault.call(&json!({ "method": "add_env", "name": "OPENAI_API_KEY", "value": "sk-real-value" }));
    let items = vault.call(&json!({ "method": "items" }));
    assert_eq!(items[0]["name"], "OPENAI_API_KEY");
    assert_eq!(items[0]["hosts"][0], "api.openai.com", "the library's rules apply");
    assert!(!items.to_string().contains("sk-real-value"), "a list never holds a value");
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "OPENAI_API_KEY" }))["value"], "sk-real-value");

    vault.call(&json!({ "method": "remove", "name": "OPENAI_API_KEY" }));
    assert_eq!(vault.call(&json!({ "method": "items" })), json!([]));
    vault.call(&json!({ "method": "undo" }));
    assert_eq!(vault.call(&json!({ "method": "items" })).as_array().unwrap().len(), 1);

    vault.call(&json!({ "method": "lock" }));
    assert_eq!(vault.call(&json!({ "method": "status" }))["unlocked"], false);
    vault.call(&json!({ "method": "stop" }));
}

#[test]
fn every_kind_of_item_goes_through_the_librarys_rules() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);

    vault.call(&json!({ "method": "add_login", "name": "github.com", "username": "me", "password": "chosen" }));
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "github.com" }))["password"], "chosen");
    assert_eq!(vault.call(&json!({ "method": "item", "name": "github.com" }))["urls"][0], "https://github.com");
    vault.call(&json!({ "method": "add_login", "name": "tax.info", "urls": ["https://irs.gov/login"], "password": "x" }));
    assert_eq!(vault.call(&json!({ "method": "item", "name": "tax.info" }))["urls"], json!(["https://irs.gov/login"]), "given sites replace a guess");

    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    vault.call(
        &json!({ "method": "add_login", "name": "two-factor", "urls": ["https://a.example", "https://b.example"], "password": "x", "totp": secret }),
    );
    assert_eq!(vault.call(&json!({ "method": "item", "name": "two-factor" }))["urls"].as_array().unwrap().len(), 2);
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "two-factor" }))["totp"], secret);
    let bad = json!({ "method": "add_login", "name": "bad-code", "password": "x", "totp": "not a secret!" });
    assert!(vault.raw(&bad.to_string()).get("error").is_some(), "a two-factor secret that cannot work is refused");

    vault.call(&json!({ "method": "add_login", "name": "generated" }));
    let generated = vault.call(&json!({ "method": "reveal", "name": "generated" }));
    assert_eq!(generated["password"].as_str().unwrap().chars().count(), 28, "{generated}");

    let mut meta = vault.call(&json!({ "method": "item", "name": "generated" }));
    meta.as_object_mut().unwrap().remove("space");
    meta["username"] = json!("changed");
    vault.call(&json!({ "method": "edit", "name": "generated", "meta": meta }));
    assert_eq!(vault.call(&json!({ "method": "item", "name": "generated" }))["username"], "changed");
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "generated" }))["password"], generated["password"], "an edit with no secret keeps it");

    vault.call(&json!({ "method": "add_note", "name": "plan", "body": "one\ntwo" }));
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "plan" }))["body"], "one\ntwo");

    vault.call(&json!({ "method": "add_ssh", "name": "deploy", "private_key": "key" }));
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "deploy" }))["private_key"], "key");

    let card = json!({ "method": "add_card", "name": "Visa", "number": "4242424242424242", "expiry": "12/30", "cvc": "123", "holder": "A Person" });
    vault.call(&card);
    assert!(vault.call(&json!({ "method": "item", "name": "Visa" }))["hint"].as_str().unwrap().contains("4242"));
    let bad = json!({ "method": "add_card", "name": "Bad", "number": "1234", "expiry": "12/30", "cvc": "123", "holder": "A Person" });
    assert!(vault.raw(&bad.to_string()).get("error").is_some(), "a bad card number is refused");

    assert!(vault.raw(&json!({ "method": "add_note", "name": "plan", "body": "again" }).to_string()).get("error").is_some(), "adding never replaces");

    let mut meta = vault.call(&json!({ "method": "item", "name": "Visa" }));
    meta.as_object_mut().unwrap().remove("space");
    let secret = json!({ "type": "card", "number": "5555555555554444", "expiry": "01/31", "cvc": "999", "holder": "A Person" });
    vault.call(&json!({ "method": "edit", "name": "Visa", "meta": meta, "secret": secret }));
    assert!(vault.call(&json!({ "method": "item", "name": "Visa" }))["hint"].as_str().unwrap().contains("4444"), "the hint follows the number");
    assert_eq!(vault.call(&json!({ "method": "expiring" })), json!([]), "a card good until 2031 is not running out");
    vault.call(&json!({ "method": "stop" }));
}

#[test]
fn an_item_changes_and_its_old_versions_can_come_back() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);

    vault.call(&json!({ "method": "add_login", "name": "github.com", "username": "me", "password": "first" }));
    let mut meta = vault.call(&json!({ "method": "item", "name": "github.com" }));
    meta.as_object_mut().unwrap().remove("space");
    meta["username"] = json!("someone else");
    vault.call(&json!({ "method": "edit", "name": "github.com", "meta": meta, "secret": { "type": "login", "password": "second" } }));
    assert_eq!(vault.call(&json!({ "method": "item", "name": "github.com" }))["username"], "someone else");
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "github.com" }))["password"], "second");

    assert_eq!(vault.call(&json!({ "method": "history", "name": "github.com" })).as_array().unwrap().len(), 2);
    vault.call(&json!({ "method": "restore", "name": "github.com", "version": 0 }));
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "github.com" }))["password"], "first");

    vault.call(&json!({ "method": "remove", "name": "github.com" }));
    let history = vault.call(&json!({ "method": "history", "name": "github.com" }));
    assert_eq!(history.as_array().unwrap().last().unwrap()["deleted"], true);
    vault.call(&json!({ "method": "restore", "name": "github.com", "version": 1 }));
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "github.com" }))["password"], "second");
    vault.call(&json!({ "method": "stop" }));
}

#[test]
fn a_file_is_previewed_as_counts_then_imported_as_one_batch() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);
    let file = dir.path().join("secrets.env");
    std::fs::write(&file, "API_KEY=real-value\nOTHER=2\n").unwrap();

    let preview = vault.call(&json!({ "method": "import_read", "path": file }));
    assert_eq!(preview["variables"], 2);
    assert!(!preview.to_string().contains("real-value"), "a preview holds counts");
    assert_eq!(vault.call(&json!({ "method": "items" })), json!([]), "reading writes nothing");

    assert_eq!(vault.call(&json!({ "method": "import_finish" }))["added"], 2);
    assert_eq!(vault.call(&json!({ "method": "items" })).as_array().unwrap().len(), 2);
    vault.call(&json!({ "method": "undo" }));
    assert_eq!(vault.call(&json!({ "method": "items" })), json!([]), "one undo removes the import");
    vault.call(&json!({ "method": "stop" }));
}

#[test]
fn the_recovery_key_is_replaced_only_after_the_new_one_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);
    let archive = dir.path().join("vault.archive");

    assert!(vault.raw(r#"{"method":"rotation_finish"}"#).get("error").is_some(), "there is nothing to finish");
    vault.call(&json!({ "method": "rotation_begin" }));
    let words = vault.call(&json!({ "method": "rotation_words" }));
    let list: Vec<&str> = words.as_str().unwrap().split(' ').collect();
    assert_eq!(list.len(), 24);
    for position in vault.call(&json!({ "method": "rotation_positions" })).as_array().unwrap() {
        let word = list[usize::try_from(position.as_u64().unwrap()).unwrap()];
        assert_eq!(vault.call(&json!({ "method": "rotation_check_word", "position": position, "answer": word })), true);
    }
    vault.call(&json!({ "method": "rotation_finish" }));

    vault.call(&json!({ "method": "export_archive", "path": archive }));
    vault.call(&json!({ "method": "stop" }));

    let fresh = dir.path().join("recovered");
    let recovered = Handle::open(&fresh);
    recovered.call(&json!({ "method": "recover_open", "source": archive, "words": words, "as_it_stood": false }));
    assert_eq!(recovered.call(&json!({ "method": "recover_problems" })), json!([]));
    let histories = recovered.call(&json!({ "method": "recover_histories" }));
    assert_eq!(histories, json!([{ "devices": ["test mac"], "newest_items": [] }]), "one history, so nothing to choose");
    assert!(recovered.raw(r#"{"method":"recover_choose","index":1}"#).get("error").is_some());
    recovered.call(&json!({ "method": "recover_choose", "index": 0 }));
    recovered.call(&json!({ "method": "recover_finish", "passphrase": PASSPHRASE, "device_name": "new mac" }));
    recovered.call(&json!({ "method": "connect", "passphrase": PASSPHRASE }));
    assert_eq!(
        recovered.call(&json!({ "method": "devices" })).as_array().unwrap().iter().filter(|device| device["is_this_device"] == true).count(),
        1
    );
    recovered.call(&json!({ "method": "stop" }));
}

#[test]
fn backups_grants_and_two_factor_codes_go_through_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);
    vault.call(&json!({ "method": "unlock" }));

    let folder = dir.path().join("backup");
    std::fs::create_dir(&folder).unwrap();
    vault.call(&json!({ "method": "add_backup", "folder": folder }));
    let status = vault.call(&json!({ "method": "status" }));
    assert_eq!(status["backups"].as_array().unwrap().len(), 1);
    assert_eq!(vault.call(&json!({ "method": "verify_backup", "folder": folder }))["devices"], 1);
    vault.call(&json!({ "method": "remove_backup", "folder": folder }));
    assert_eq!(vault.call(&json!({ "method": "status" }))["backups"], json!([]));

    let grant = vault.call(&json!({ "method": "grant", "space": "Personal", "agent": "claude", "seconds": 600 }));
    assert_eq!(vault.call(&json!({ "method": "grants" }))[0]["agent"], "claude");
    vault.call(&json!({ "method": "end_grant", "id": grant["id"] }));
    assert_eq!(vault.call(&json!({ "method": "grants" })), json!([]));

    vault.call(&json!({ "method": "add_login", "name": "github.com", "password": "x", "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" }));
    let code = vault.call(&json!({ "method": "code", "name": "github.com" }));
    assert_eq!(code["code"].as_str().unwrap().len(), 6, "{code}");
    assert!((1..=30).contains(&code["seconds_left"].as_u64().unwrap()), "{code}");
    vault.call(&json!({ "method": "stop" }));
}

#[test]
fn a_second_device_joins_when_both_people_see_the_same_words() {
    let dir = tempfile::tempdir().unwrap();
    let (first, second) = (dir.path().join("first"), dir.path().join("second"));
    let existing = new_vault(&first);
    existing.call(&json!({ "method": "unlock" }));
    existing.call(&json!({ "method": "add_env", "name": "KEY", "value": "value" }));

    let joining = Handle::open(&second);
    let port = joining.call(&json!({ "method": "join_begin", "passphrase": PASSPHRASE, "device_name": "new mac" }));

    // Each side blocks on the other, so one runs beside this thread, as a second device would.
    let address = format!("127.0.0.1:{port}");
    let words = std::thread::scope(|scope| {
        let adder = scope.spawn(|| {
            let adder = Handle::open(&first);
            adder.call(&json!({ "method": "connect", "passphrase": PASSPHRASE }));
            let words = adder.call(&json!({ "method": "pair_begin", "address": address }));
            let name = adder.call(&json!({ "method": "pair_confirm" }));
            assert_eq!(name, "new mac");
            words
        });
        let words = joining.call(&json!({ "method": "join_wait", "seconds": 30 }));
        joining.call(&json!({ "method": "join_confirm" }));
        assert_eq!(adder.join().unwrap(), words, "both screens show the same words");
        words
    });
    assert_eq!(words.as_array().unwrap().len(), 3);

    joining.call(&json!({ "method": "connect", "passphrase": PASSPHRASE }));
    joining.call(&json!({ "method": "unlock" }));
    assert_eq!(joining.call(&json!({ "method": "items" }))[0]["name"], "KEY");
    assert_eq!(existing.call(&json!({ "method": "devices" })).as_array().unwrap().len(), 2);
    existing.call(&json!({ "method": "stop" }));
    joining.call(&json!({ "method": "stop" }));
}

#[test]
fn a_wifi_network_is_saved_by_its_name_and_a_bad_card_edit_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);
    vault.call(&json!({ "method": "add_wifi", "name": "Larch", "password": "hunter22" }));
    assert_eq!(vault.call(&json!({ "method": "item", "name": "Larch" }))["kind"], "wifi");
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "Larch" }))["password"], "hunter22");
    let long = "x".repeat(33);
    assert!(vault.raw(&json!({ "method": "add_wifi", "name": long, "password": "p" }).to_string()).get("error").is_some(), "a network name is short");

    vault.call(&json!({ "method": "add_card", "name": "Visa", "number": "4242424242424242", "expiry": "12/30", "cvc": "123", "holder": "A" }));
    let mut meta = vault.call(&json!({ "method": "item", "name": "Visa" }));
    meta.as_object_mut().unwrap().remove("space");
    let bad = json!({ "method": "edit", "name": "Visa", "meta": meta, "secret": { "type": "card", "number": "1234", "expiry": "12/30", "cvc": "1", "holder": "A" } });
    assert!(vault.raw(&bad.to_string()).get("error").is_some(), "an edited number is checked like a new one");
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "Visa" }))["number"], "4242424242424242");
    vault.call(&json!({ "method": "stop" }));
}

#[test]
fn a_failure_carries_a_stable_code_and_no_result() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);
    let reply = vault.raw(r#"{"method":"reveal","name":"NOPE"}"#);
    assert_eq!(reply["code"], "not_found");
    assert!(reply.get("result").is_none());
    vault.call(&json!({ "method": "stop" }));
}

#[test]
fn nonsense_is_refused_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Handle::open(dir.path());
    for call in ["", "not json", "{}", r#"{"method":"no_such_call"}"#, r#"{"method":"add_env"}"#, "[1,2,3]"] {
        assert_eq!(vault.raw(call)["code"], "error", "{call}");
    }
}

#[test]
fn setup_steps_need_setup_to_have_begun() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Handle::open(dir.path());
    assert!(vault.raw(r#"{"method":"setup_words"}"#).get("error").is_some());
    assert!(vault.raw(r#"{"method":"setup_finish","device_name":"x"}"#).get("error").is_some());
}

#[test]
fn null_is_safe_everywhere() {
    // SAFETY: every one of these is documented to accept null.
    unsafe {
        let reply = lv_call(std::ptr::null_mut(), std::ptr::null());
        assert!(CStr::from_ptr(reply).to_str().unwrap().contains("error"));
        lv_free_string(reply);
        lv_free_string(std::ptr::null_mut());
        lv_close(std::ptr::null_mut());
    }
}

#[test]
fn a_limited_handle_never_loses_its_limit_when_the_broker_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let owner = new_vault(&home);
    owner.call(&json!({ "method": "unlock" }));
    owner.call(&json!({ "method": "create_space", "name": "Work" }));
    owner.call(&json!({ "method": "add_env", "space": "Personal", "name": "PRIVATE", "value": "x" }));
    let grant = owner.call(&json!({ "method": "grant", "space": "Work", "agent": "test", "seconds": 600 }));

    let limited = Handle::open(&home);
    limited.call(&json!({ "method": "connect", "session": grant["token"] }));
    assert!(limited.raw(r#"{"method":"items","space":"Personal"}"#).get("error").is_some(), "limited to Work");

    owner.call(&json!({ "method": "stop" }));
    owner.call(&json!({ "method": "connect", "passphrase": PASSPHRASE }));
    owner.call(&json!({ "method": "unlock" }));

    // The first call may only find the old connection gone. None may reach the other space.
    for _ in 0..3 {
        let reply = limited.raw(r#"{"method":"items","space":"Personal"}"#);
        assert!(reply.get("error").is_some(), "{reply}");
    }
    owner.call(&json!({ "method": "stop" }));
}

#[test]
fn generated_values_take_the_shape_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Handle::open(&dir.path().join("vault"));
    let plain = vault.call(&json!({ "method": "generate_password", "length": 16, "symbols": false }));
    assert!(plain.as_str().unwrap().len() == 16 && plain.as_str().unwrap().chars().all(char::is_alphanumeric), "{plain}");
    let secret = vault.call(&json!({ "method": "generate_secret", "bytes": 64 }));
    assert!(secret.as_str().unwrap().len() == 128 && secret.as_str().unwrap().chars().all(|digit| digit.is_ascii_hexdigit()), "{secret}");
    assert!(vault.raw(r#"{"method":"generate_secret","bytes":48}"#).get("error").is_some());
}

#[test]
fn a_sites_icon_is_saved_once_and_read_back_as_pixels() {
    /// One opaque red pixel.
    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir.path().join("vault"));
    vault.call(&json!({ "method": "unlock" }));
    assert_eq!(vault.call(&json!({ "method": "icon", "url": "https://github.com" })), Value::Null);
    vault.call(&json!({ "method": "save_icon", "url": "https://github.com/login", "png": PNG }));
    let icon = vault.call(&json!({ "method": "icon", "url": "https://www.github.com" }));
    assert_eq!((icon["width"].as_u64(), icon["rgba"].as_array().map(Vec::len)), (Some(1), Some(4)), "{icon}");
    assert!(vault.raw(r#"{"method":"save_icon","url":"https://x.example","png":"not base64!"}"#).get("error").is_some());
    vault.call(&json!({ "method": "stop" }));
}
