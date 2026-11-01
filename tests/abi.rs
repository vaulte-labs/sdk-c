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
        let _ = self.raw(r#"{"method":"status"}"#);
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
        assert_eq!(vault.call(&json!({ "method": "setup_check_word", "position": position, "answer": "wrong" })), false);
    }
    vault.call(&json!({ "method": "setup_finish", "device_name": "test mac" }));
    assert_eq!(vault.call(&json!({ "method": "exists" })), true);
    vault.call(&json!({ "method": "connect", "passphrase": PASSPHRASE }));
    vault
}

fn stop(home: &Path) {
    let handle = Handle::open(home);
    let _ = handle.raw(r#"{"method":"connect","passphrase":"test passphrase"}"#);
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
    stop(&home);
}

#[test]
fn every_kind_of_item_goes_through_the_librarys_rules() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);

    vault.call(&json!({ "method": "add_login", "name": "github.com", "username": "me", "password": "chosen" }));
    assert_eq!(vault.call(&json!({ "method": "reveal", "name": "github.com" }))["password"], "chosen");
    assert_eq!(vault.call(&json!({ "method": "item", "name": "github.com" }))["urls"][0], "https://github.com");

    vault.call(&json!({ "method": "add_login", "name": "generated" }));
    let generated = vault.call(&json!({ "method": "reveal", "name": "generated" }));
    assert!(generated["password"].as_str().unwrap().len() >= 16, "{generated}");

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
    stop(&home);
}

#[test]
fn a_failure_carries_a_stable_code_and_no_result() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let vault = new_vault(&home);
    let reply = vault.raw(r#"{"method":"reveal","name":"NOPE"}"#);
    assert_eq!(reply["code"], "not_found");
    assert!(reply.get("result").is_none());
    stop(&home);
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
fn null_is_safe_to_free_and_close() {
    // SAFETY: both are documented to accept null.
    unsafe {
        lv_free_string(std::ptr::null_mut());
        lv_close(std::ptr::null_mut());
    }
}
