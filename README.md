# irchub

A hub server for coordinating networks of IRC bots. irchub handles encrypted configuration distribution, bot registration, and inter-hub mesh networking — so your bots always have up-to-date users, keys and settings without manual intervention.

There are no admin, oper or bot passwords: every hub, bot, admin and oper has its own Curve25519 keypair (Ed25519 for signatures + X25519 for encryption), and only public keys are ever exchanged. The one password left is each program's config-file password. Design: `docs/passwordless.md`.

> **Companion project:** irchub is designed to work with [ircbot](https://github.com/robertclemens/ircbot/) — a C-based IRC bot that connects to irchub for secure configuration sync, op coordination, and inter-bot communication. You need both projects to run a complete setup.

## Overview

irchub sits between your IRC bots and your admin console. Each [ircbot](https://github.com/robertclemens/ircbot/) instance authenticates to the hub using its own Curve25519 keypair. The hub distributes encrypted configuration (channels, admins and opers with their public keys and usermasks, the other bots' public keys) to all connected bots and keeps everything synchronized across multiple hub instances via a peer mesh.

```
hub_admin ──► irchub ──► ircbot A
                    └──► ircbot B
                    └──► irchub (peer) ──► ircbot C
```

**Key capabilities:**

- **Bot registration** — each bot makes its own keypair; you register its UUID and public key
- **Encrypted config sync** — AES-256-GCM encrypted configuration pushed to all bots on connect and periodically
- **Peer mesh** — multiple hub instances synchronize state; leader election prevents duplicate operations
- **Admin console** — interactive TUI (`hub_admin`) for managing bots, channels, masks, and opers
- **IP access control** — allowlist/denylist with CIDR support
- **Rate limiting** — per-IP connection limits and failed-auth blocking
- **Tombstone purging** — automatic cleanup of deleted config entries with configurable retention

## Components

| Binary | Purpose |
|--------|---------|
| `irchub` | Hub server |
| `hub_admin` | Interactive admin console |
| `keygen` | Makes an admin/oper keypair (`<ts>_<name>.private.b64` / `.public.b64`) |
| `hub_decrypt` | Decrypt and inspect config file |
| `hub_encrypt` | Re-encrypt a config file |

Built binaries are placed in `bin/`. Install them wherever suits your setup — the examples below assume the binaries are on your `PATH` or you are running from the directory containing them.

## Companion Project: ircbot

irchub is the hub — [ircbot](https://github.com/robertclemens/ircbot/) is the bot. The two projects are built to work together:

- **[ircbot](https://github.com/robertclemens/ircbot/)** connects to irchub on startup, authenticates with its Curve25519 keypair, and receives its full configuration (channels to join, admins and opers with their public keys and usermasks, the other bots' public keys) automatically.
- When a bot's config changes (new channel, new user, a changed key, rekey), the hub pushes the update to all connected bots in real time.
- Bots request op grants through the hub, which coordinates across the mesh so any bot can grant ops to any other bot regardless of which hub they are connected to. With no hub reachable, bots ask each other directly with PRIVMSGs sealed to each other's keys.
- Admins and opers command a bot over IRC with their own key: a signed auth request, a lockbox reply carrying the bot's public key, then commands sealed to the bot. The hub only distributes public keys — it never holds a user's or a bot's private key.

You provision bots and manage the network entirely through `hub_admin` — you never need to manually edit bot config files.

## Dependencies

| Dependency | Minimum | Notes |
|------------|---------|-------|
| GCC | 7+ | C11 support required (`-std=c11`) |
| OpenSSL | 1.1.1+ | `libssl`, `libcrypto` — EVP API required |
| POSIX | — | Linux, FreeBSD, and other POSIX systems (uses `termios`, `flock`, POSIX sockets) |
| GNU Make | 3.81+ | Build system |

### Debian / Ubuntu

```bash
sudo apt install build-essential libssl-dev
```

### RHEL / CentOS / Fedora

```bash
sudo dnf install gcc make openssl-devel
# or for older systems:
sudo yum install gcc make openssl-devel
```

### Arch Linux

```bash
sudo pacman -S gcc make openssl
```

## Building

```bash
git clone https://github.com/robertclemens/irchub.git
cd irchub
make
```

Built binaries are placed in `bin/`.

**Build modes:**

```bash
make              # Release build (default) — optimized, hardened
make debug        # Debug build with AddressSanitizer and UBSan
make production   # Maximum optimization (LTO, -march=native)
make clean        # Remove build artifacts
```

## Initial Setup

### 1. Run setup

First make the first admin's keypair, on that admin's own machine:

```bash
./keygen robert        # or run ./keygen and type the name
```

This writes `YYYYMMDDHHMMSS_robert.private.b64` (mode 0600 — it stays on that machine; `hub_admin` and the IRC scripts use it) and `YYYYMMDDHHMMSS_robert.public.b64`, and prints the public key and its fingerprint. The private key is never printed. (`keygen.c` is byte-identical to `ircbot/utils/keygen.c`; `ircbot/utils/README.txt` has an equivalent openssl recipe.)

Then run setup from the directory where irchub will store its files (config, PID, log, and password files are all created relative to the working directory):

```bash
./irchub -setup
```

You will be prompted for:

| Prompt | Description |
|--------|-------------|
| **Port** | TCP port the hub listens on (e.g. `6697`) |
| **Bind IP** | Interface to bind to — press Enter to default to `0.0.0.0` (all interfaces) |
| **Friendly Name** | Human-readable name for this hub instance |
| **Config Password** | Password used to encrypt the config file (hidden input) |
| **First admin** | Name, then the admin's **public** key — paste the 88 characters or give the path of the `.public.b64` (a `.private.b64` is refused); confirm by fingerprint; then one or more usermasks |

Setup generates this hub's own Curve25519 keypair (the private key stays inside the encrypted config), prints the hub's UUID and public key and saves the public key to `hub_public.b64`, writes the encrypted config file (`.irchub.cnf`) and exits. The hub does not start automatically.

### 2. Start the hub

```bash
./irchub
```

irchub daemonizes itself — it double-forks, detaches from the terminal, and writes its PID to `.irchub.pid`. The working directory is preserved so all relative file paths resolve correctly.

By default, irchub prompts for the config password on stdin before daemonizing. If you are starting it interactively this is the safest option — the password is never stored anywhere and is only held in process memory for the duration of the initial config load.

To stop the hub:

```bash
kill $(cat .irchub.pid)
```

### 3. Create a password file (optional — required for unattended start)

By default a password must be typed each time irchub starts. To allow unattended or automated starts, create an encrypted machine-bound password file:

```bash
./irchub -p
```

This prompts for the config password (with confirmation), then writes `.irchub.pass` — an AES-256-GCM encrypted file readable only by the current user (`0600`). The encryption key is derived from stable properties of this machine and user account, so the file cannot be decrypted if copied to another host.

When `.irchub.pass` is present and passes validation (correct ownership, `0600` permissions, GCM tag intact), irchub reads the password from it automatically and no interactive input is required. If the file is absent, has wrong permissions, or fails decryption, irchub falls back to the stdin prompt.

### 4. Auto-start (optional — requires password file)

A crontab entry can keep irchub running automatically. Because cron cannot provide interactive input, this requires `.irchub.pass` to exist (see step 3). irchub rejects duplicate starts via PID file locking, so running it on an interval is safe — if it is already running the new invocation exits immediately.

Add a crontab entry that checks every 5 minutes:

```bash
crontab -e
```

```
*/5 * * * * /full/path/to/irchub
```

Replace `/full/path/to/irchub` with the absolute path to the binary. Note that cron executes from your home directory by default — if your irchub files live in a subdirectory, place the binary there or ensure the config files (`.irchub.cnf`, `.irchub.pass`) exist in the directory cron will use as the working directory.

## Admin Console

`hub_admin` logs in with an admin's **private key file** — there is no username or password:

```bash
./hub_admin <hub-ip> <hub-port> <YYYYMMDDHHMMSS_name.private.b64>
```

The hub finds the admin record by the key and the admin proves it holds the key by signing a one-time challenge (a fresh ephemeral session key per login, so a captured login cannot be replayed). Keys an older hub created (`admin_<name>.b64`) are the same format and keep working. Keep the file `chmod 600`; `hub_admin` warns if it is not. Admins created on IRC with `+admin` can log in too — run production networks with opt `h` (below) if you want only hub admins to create users.

### Admin Menu

```
IRC HUB ADMIN CONSOLE

  1. Manage Bots
  2. Manage Peer Connections
  3. Manage Local Peer Config
  4. Manage Global Peer Config      (opt flags)
  5. IRC Admin Commands             (admins, opers, usermasks, channels, op)
  6. Exit
```

### Adding a Bot

1. On the bot's machine run `./ircbot -setup`; the bot generates its own keypair and prints its UUID, public key and key fingerprint.
2. **Manage Bots → Add Bot**, then enter the bot's nickname, UUID and 88-character public key.

The hub never sees a bot's private key. Every bot receives the other bots' public keys (`b|` lines), which it uses to seal bot-to-bot requests (OPME, INVITE, SETNICK) when no hub is reachable.

### Rekeying a Bot

Rekeying is bot-local: only the bot holds its private key. **Manage Bots → Rekey Bot** shows the instructions — an admin runs the bot's own `rekey` command, the bot makes a new keypair, pushes the new public key to the hub and reconnects.

### Admins and Opers

**IRC Admin Commands → Manage Admins / Manage Opers**:

- **Add Admin / Add Oper** — name, the user's **public key** (they run `keygen <name>` and send you the `.public.b64`; paste it or give its path; a `.private.b64` is refused), confirm the fingerprint, then a usermask. Each key may belong to one user only.
- **Change User Public Key** — replaces a key (rotation, a lost key, or a legacy user with no key). UUID and usermasks are kept; the old key stops working on the hub and on every bot as soon as it syncs.
- **List Admins / Opers**, **Match User** — show each key's fingerprint.

Only admins can log into `hub_admin`; an oper's key is refused.

### Opt flags

**Manage Global Peer Config → Set Opt Flags**. Flag `h` (hub-only mutations) makes every bot refuse local `+admin`/`-admin`, `+oper`/`-oper`, `+usermask`/`-usermask`, `+bot`/`-bot`, `join`/`part` and `chkey`, so users, masks, keys and channels change only through `hub_admin`. Set an empty string to clear it.

## Peer Mesh

Multiple hub instances can be linked to share configuration and bot state. Add a peer from **Manage Peer Connections → Add Peer**. Provide the peer's IP, port, UUID, friendly name and public key (its `hub_public.b64`). Peers authenticate each other with Ed25519 signatures (`HUBv3`); a pre-passwordless hub (`HUBv2`) is refused, so upgrade all hubs together.

Connected peers:
- Synchronize bot config and global config entries
- Forward bot-to-bot op requests across hub boundaries
- Propagate tombstone purges with deduplication to prevent loops
- Elect a leader (hub with lexicographically smallest UUID) for scheduled operations

## Configuration

The config file (`.irchub.cnf`) is AES-256-GCM encrypted with a key derived from your config password via PBKDF2-SHA256 (100,000 iterations). It is never stored in plaintext.

**Global settings managed via `hub_admin`:**

| Setting | Command |
|---------|---------|
| Bind IP | Manage Local Peer Config → Set Bind IP |
| Bind Port | Manage Local Peer Config → Set Bind Port |
| Hub Name | Manage Local Peer Config → Set Hub Name |
| Log Level | Manage Local Peer Config → Set Log Level (0–4) |
| Log Size Limit | Manage Local Peer Config → Set Log Size Limit |
| IP Allowlist | Manage Local Peer Config → Manage IP Allowlist |
| IP Denylist | Manage Local Peer Config → Manage IP Denylist |
| Tombstone Purge | Manage Local Peer Config → Purge Tombstones |
| Auto Purge Schedule | Manage Local Peer Config → Configure Automatic Purge |
| Admins (keys, masks) | IRC Admin Commands → Manage Admins |
| Opers (keys, masks) | IRC Admin Commands → Manage Opers |
| Channels | IRC Admin Commands → Manage Channels |
| Opt flags (`h`) | Manage Global Peer Config → Set Opt Flags |

## Utilities

### Decrypt config (inspection / debugging)

```bash
./hub_decrypt [config-file]                # defaults to .irchub.cnf
./hub_decrypt .irchub.cnf > config.txt     # raw plaintext, nothing else
```

Prompts for the config password (no echo) and writes the raw plaintext config to stdout — no banner or framing, so it can be redirected or piped. The prompt goes to the terminal and errors to stderr. When stdin is not a terminal, the first line of stdin is taken as the password (`echo "$PW" | ./hub_decrypt`); the password is never passed as an argument.

### Encrypt config

```bash
./hub_encrypt [plaintext-file] [output-file]   # defaults: config.txt, .irchub.cnf
```

Re-encrypts a plaintext config file. Useful for migrating or restoring configs. Prompts for the password twice (or reads one line from a non-terminal stdin), then writes the output mode 0600 via a temp file and rename, so a failed run never leaves a truncated config. Input that does not look like a plaintext config (e.g. an already-encrypted file) is refused.

### Make an admin/oper keypair

```bash
./keygen [name]          # prompts for the name when none is given
```

Writes `YYYYMMDDHHMMSS_<name>.private.b64` (mode 0600) and `YYYYMMDDHHMMSS_<name>.public.b64` in the current directory, never overwriting an existing file, and prints the public key and its fingerprint (e.g. `763e:58a6:2dfd:ae02`) — never the private key. Names are 1–32 characters of `A-Z a-z 0-9 _ . -`, not starting with `.` or `-`. Hubs and bots make their own keys during `-setup`; keygen is for the people who command them.

## Security Notes

- The config password is never passed on the command line or stored in an environment variable. It is read from `.irchub.pass` (if present) or prompted on stdin at startup.
- `.irchub.pass` is AES-256-GCM encrypted and machine-bound — it cannot be decrypted on a different host. The file must be owned by the current user with permissions `0600`; any deviation is rejected and irchub falls back to the stdin prompt.
- All bot-to-hub communication is encrypted with AES-256-GCM using per-session keys negotiated via Curve25519 (sealed-box).
- Failed authentication attempts are tracked per IP. After 3 failures the IP is blocked for 5 minutes; the failure counter resets after 1 hour. These thresholds are compile-time constants (`MAX_FAILED_AUTH_ATTEMPTS`, `FAILED_AUTH_BLOCK_DURATION`, `FAILED_AUTH_RESET_TIME` in `hub.h`) — adjust and rebuild to change them. Specific IPs and ranges can be permanently allowed or blocked at runtime via **Manage Peer Config → Manage IP Allowlist / Manage IP Denylist** in `hub_admin` (supports CIDR notation).
- Each IP is limited to 5 simultaneous connections (`MAX_CONNECTIONS_PER_IP` in `hub.h` — compile-time constant).
- Private key material is wiped from memory (`secure_wipe`) as soon as it is no longer needed.
- No private key ever crosses the network: bots, admins and opers make their own keypairs and only public keys are registered and synced. `hub_admin` logins sign a one-time challenge; captured logins cannot be replayed.
- Mixed-version rollout is fail-closed: bots that have not advertised protocol `v|2` get records with an empty password slot, and pre-passwordless hubs are refused as peers (`docs/passwordless.md` §9).

## Files

| File | Description |
|------|-------------|
| `.irchub.cnf` | Encrypted config file (created by `-setup`) |
| `.irchub.pass` | Encrypted password file (created by `-p`, optional) |
| `.irchub.pid` | PID file (created on start, removed on clean stop) |
| `.irchub.log` | Log file (rotating, default 10 MB limit) |

All files are created relative to the working directory at the time irchub is invoked.

## Log Levels

Logging is disabled by default. Set the level at runtime via **Manage Peer Config → Set Log Level** in `hub_admin`:

| Level | Name | Output |
|-------|------|--------|
| 0 | NONE | No logging (default) |
| 1 | ERROR | Errors only |
| 2 | WARNING | Errors and warnings |
| 3 | INFO | Errors, warnings, and info |
| 4 | DEBUG | Everything |

## Quick Reference

```bash
# Build
make

# First-time setup
./irchub -setup

# Start hub — prompts for password interactively
./irchub

# Stop hub
kill $(cat .irchub.pid)

# (Optional) Create encrypted password file for unattended start
./irchub -p

# (Optional) Auto-start via crontab — check every 5 minutes
# */5 * * * * /full/path/to/irchub

# Make an admin keypair (on the admin's machine)
./keygen robert

# Connect admin console (with the admin's PRIVATE key file)
#./hub_admin <hub ip> <hub port> <private key file>
./hub_admin 127.0.0.1 6697 20260914120000_robert.private.b64

# View logs (if logging has been turned on)
tail -f .irchub.log

# Inspect config (debug)
./hub_decrypt
```
