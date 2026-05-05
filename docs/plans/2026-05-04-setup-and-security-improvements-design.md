# Design: Setup & Security Improvements

Date: 2026-05-04  
Branch: test  
Approach: Focused in-place edits (Approach 1)

## Summary

Seven targeted changes across four files. No new files introduced. No structural refactoring.

## Changes by File

### `hub.h`
- Add `#define CONFIG_PASS_ENV_VAR "HUB_PASS"`

### `hub_main.c`

**Remove `-d` flag and `daemonize()`**  
Delete the `daemonize()` function and all code that detects or calls it.

**Rework argument parsing**  
Old usage: `./irchub <pass> [-setup] [-d]`  
New usage: `./irchub [-setup]`

- Scan `argv[]` for `-setup` flag only (no positional password argument).
- Normal mode: call `getenv(CONFIG_PASS_ENV_VAR)`; exit with a clear error message if unset or empty.
- Setup mode: all input is interactive (never reads `HUB_PASS`).

**Fix bind IP hang in setup**  
Replace `scanf("%63s", state.bind_ip)` with `fgets` + strip newline. Empty input defaults to `"0.0.0.0"`.

**Add inline keypair generation in setup**  
After friendly name prompt, show a numbered menu:
```
Hub Keypair:
  1. Generate new keypair
  2. Use existing key file
```
- Option 1: call `hub_crypto_generate_keypair()` in-process; load result directly into `state.private_key_pem`.
- Option 2: prompt for file path (existing behaviour).

**Add config password prompt in setup**  
Replace the removed `argv[1]` source with an interactive `get_password_secure()` call for the config password. No confirm prompt (it only encrypts the local config file, not a shared credential).

**Confirm admin password in setup**  
After the admin password prompt, ask again. Re-prompt until both inputs match.

**Remove valgrind target stale reference**  
The `valgrind` make target passes a password argument to the hub binary; update it.

### `hub_admin.c`

**Bot add/rekey: replace auto-export with a choice menu**  
In `bot_add()`, after receiving a successful `SUCCESS|uuid|privkey` response, instead of automatically saving to file and printing IRC commands, show:
```
Key Distribution:
  1. Export to file
  2. Show private key (base64)
  3. Show IRC sethubkey commands
```
- Option 1: save `bot_<nick>_priv_key.b64` (current auto-save behaviour).
- Option 2: print the raw base64 key to stdout.
- Option 3: print the `/msg <nick> sethubkey N/T:<chunk>` sequence (current IRC output behaviour).

Apply the same menu to `bot_rekey()` for the manual-update path (bot was disconnected). The auto-update path (`AUTO-UPDATED`) is unchanged — no key needs distributing.

### `run_hub.sh`
- Export `HUB_PASS` before launching the binary; remove the password from the command line.
- Update comments to reflect new usage.

```bash
export HUB_PASS="configpasswordhere"
...
./irchub &
```

### `Makefile`
- Remove `LDFLAGS = -L/usr/lib -L/usr/local/lib`. These paths are in the linker's default search and explicitly adding them causes the "skipping incompatible" warnings on multiarch systems.
- Update stale usage strings in the `install` help text, `valgrind` target, and the `help` target to reflect the new `./irchub [-setup]` invocation.

## What Is Not Changing
- Protocol, crypto, config file format, admin protocol — untouched.
- `hub_admin.c` argument parsing and authentication flow — untouched.
- `keygen.c` — untouched (still useful as a standalone key-generation utility).
- All other source files — untouched.

## Compiler Warning Root Cause
The `skipping incompatible /usr/lib/libgcc_s.so.1` warning appears because the Makefile explicitly adds `/usr/lib` to the linker search path (`-L/usr/lib`). On multiarch systems, `/usr/lib` contains 32-bit objects; the linker tries them, rejects them, then finds the correct 64-bit ones via its own default paths. Removing the explicit `-L` flags eliminates the noise entirely without affecting the build output.
