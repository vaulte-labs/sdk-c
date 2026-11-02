//! The C ABI over libvault. Four functions carry JSON, so every SDK shares one implementation of
//! the protocol and a new capability is a new [`call::Call`], not a new symbol. Policy stays in
//! the broker: nothing here can do what `vlt` could not.

#[cfg(all(feature = "test-hooks", not(debug_assertions)))]
compile_error!("test-hooks stand in for a person, so they must never reach a release build");

mod call;
mod vault;

use std::ffi::{CStr, CString, c_char};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, PoisonError};

use libvault::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::call::Call;
use crate::vault::Vault;

pub struct LvHandle(Mutex<Vault>);

fn into_reply(json: &[u8]) -> *mut c_char {
    // JSON escapes NUL, so this cannot fail.
    CString::new(json).map_or(ptr::null_mut(), CString::into_raw)
}

fn error_reply(error: &Error) -> *mut c_char {
    let reply = serde_json::json!({ "error": error.to_string(), "code": error.code() });
    into_reply(reply.to_string().as_bytes())
}

/// Opens a handle on the vault at `home`, or the default one when `home` is null. Returns null
/// when `home` is not UTF-8.
///
/// # Safety
/// `home` is null or a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lv_open(home: *const c_char) -> *mut LvHandle {
    let home = if home.is_null() {
        libvault::default_home()
    } else {
        // SAFETY: the caller promises a valid string.
        let home = unsafe { CStr::from_ptr(home) };
        match home.to_str() {
            Ok(home) => PathBuf::from(home),
            Err(_) => return ptr::null_mut(),
        }
    };
    Box::into_raw(Box::new(LvHandle(Mutex::new(Vault::new(home)))))
}

/// Runs one JSON call. The reply is `{"result":...}` or `{"error":"...","code":"..."}`, never null,
/// and goes to [`lv_free_string`]. Blocks while a person answers a prompt.
///
/// # Safety
/// `handle` is null or came from [`lv_open`] and is not closed, by this thread or another. `call`
/// is null or a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lv_call(handle: *mut LvHandle, call: *const c_char) -> *mut c_char {
    if handle.is_null() || call.is_null() {
        return error_reply(&Error::Usage("that call makes no sense"));
    }
    // SAFETY: neither is null, and the caller promises both are valid.
    let (handle, call) = unsafe { (&*handle, CStr::from_ptr(call)) };
    let call: Call = match serde_json::from_slice(call.to_bytes()) {
        Ok(call) => call,
        Err(_) => return error_reply(&Error::Usage("that call makes no sense")),
    };
    match handle.0.lock().unwrap_or_else(PoisonError::into_inner).run(call) {
        Ok(result) => {
            let mut reply = Zeroizing::new(Vec::with_capacity(result.len() + 11));
            reply.extend_from_slice(b"{\"result\":");
            reply.extend_from_slice(&result);
            reply.push(b'}');
            into_reply(&reply)
        }
        Err(error) => error_reply(&error),
    }
}

/// Erases and frees a reply, which may hold a secret.
///
/// # Safety
/// `value` is null or came from [`lv_call`], and is freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lv_free_string(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: the caller promises this came from `CString::into_raw`.
        let value = unsafe { CString::from_raw(value) };
        value.into_bytes_with_nul().zeroize();
    }
}

/// # Safety
/// `handle` is null or came from [`lv_open`], and is closed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lv_close(handle: *mut LvHandle) {
    if !handle.is_null() {
        // SAFETY: the caller promises this came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    }
}
