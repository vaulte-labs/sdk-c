/* The C ABI over libvault. Four functions carry JSON, so every SDK shares one implementation of
 * the protocol and a new capability is a new call, not a new symbol. See src/call.rs for the calls. */
#ifndef VAULTY_H
#define VAULTY_H

typedef struct LvHandle LvHandle;

/* Opens a handle on the vault at `home`, or the default one when `home` is NULL. Touches nothing. */
LvHandle *lv_open(const char *home);

/* Runs one JSON call and returns `{"result":...}` or `{"error":"...","code":"..."}`. Never NULL.
 * Blocks for as long as a person takes to answer a prompt, so call it off the main thread.
 * Free the reply with lv_free_string. */
char *lv_call(LvHandle *handle, const char *call);

/* Erases and frees a reply, which may hold a secret. */
void lv_free_string(char *value);

void lv_close(LvHandle *handle);

#endif
