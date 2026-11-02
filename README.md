# Vaulte SDK: the C ABI

The C ABI over [libvault](https://github.com/vaulte-labs/libvault) that every Vaulte app and SDK is
built on, including the Mac app and the [TypeScript SDK](https://github.com/vaulte-labs/ts). Use it
to bring Vaulte to another language.

Four functions carry JSON, so every SDK shares one implementation of the protocol, and a new
capability is a new call, not a new symbol:

```c
#include "vaulty.h"

LvHandle *vault = lv_open(NULL);                          /* the default vault; touches nothing */
char *reply = lv_call(vault, "{\"method\":\"items\"}");   /* {"result":...} or {"error":"...","code":"..."} */
/* ... */
lv_free_string(reply);                                    /* erases it first: a reply may hold a secret */
lv_close(vault);
```

`lv_call` blocks for as long as a person takes to answer a prompt, so call it off the main thread.
Every call, with its fields, is documented in [src/call.rs](src/call.rs). A call is
`{"method": ...}` in snake case plus its fields, such as
`{"method":"reveal","space":"Work","name":"OPENAI_API_KEY"}`.

The secrets themselves never live in your process. A handle talks to `lvd`, the broker that holds
the keys, and starts it when needed, so ship `lvd` beside your program or on `PATH`.

## Build

Clone [libvault](https://github.com/vaulte-labs/libvault) beside this repository, since the crate
depends on `../libvault`. You need Rust (pinned in `mise.toml`) and, on a Mac, Xcode 26 or its
Command Line Tools.

```sh
cargo build --release                                          # target/release/libvaulty.a
cargo rustc --release --lib --crate-type cdylib                # libvaulty.dylib, for FFI such as Bun's
cargo build --release --bin lvd --manifest-path ../libvault/Cargo.toml   # the broker to ship with it
```

Link with `-lvaulty` and include [include/vaulty.h](include/vaulty.h). From Swift, add `include/` to
the import paths and `import CVaulty`.

## Test

```sh
scripts/check.sh    # format, Clippy, and the ABI tests against the real broker
```

It must pass before every commit.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/vaulte-labs/.github/blob/main/CONTRIBUTING.md). Report a
vulnerability privately from the **Security** tab, as
[SECURITY.md](https://github.com/vaulte-labs/.github/blob/main/SECURITY.md) explains.

## License

[AGPL-3.0-only](LICENSE). If its terms don't suit you, a [commercial license](COMMERCIAL.md) is
available.
