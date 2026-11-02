/* The C ABI over libvault. Four functions carry JSON, so every SDK shares one implementation of
 * the protocol and a new capability is a new call, not a new symbol. See src/call.rs for the calls.
 *
 * Every reply is `{"result":...}` or `{"error":"...","code":"..."}`, where code is one of:
 *   error             anything else; the message says what happened
 *   locked            the vault is locked, or nobody answered the prompt in time
 *   needs_passphrase  a vault with no secure hardware needs its passphrase; ask and call again
 *   denied            the person said no, or this caller may not do that
 *   not_found         no such vault, space, item or version
 *   needs_person      only a person can do this, at their device
 *   needs_host        a secret has no host it may be sent to
 *   outdated          the broker running is older than this library; restart it */
#ifndef VAULTY_H
#define VAULTY_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LvHandle LvHandle;

/* Opens a handle on the vault at `home`, or the default one when `home` is NULL. `home` is copied.
 * Touches nothing. Returns NULL only when `home` is not UTF-8. */
LvHandle *lv_open(const char *home);

/* Runs one JSON call and returns its reply. Never NULL; a NULL handle or call gets an error reply.
 * Safe from any thread. Calls on one handle run one at a time, so a call waiting for a person
 * holds up the others: open one handle per thread to run calls side by side. Blocks for as long as
 * a person takes to answer a prompt, so call it off the main thread. Free the reply with
 * lv_free_string. */
char *lv_call(LvHandle *handle, const char *call);

/* Erases and frees a reply, which may hold a secret. NULL is ignored. */
void lv_free_string(char *value);

/* Frees the handle. No lv_call may be running on it, on any thread. NULL is ignored. */
void lv_close(LvHandle *handle);

#ifdef __cplusplus
}
#endif

#endif
