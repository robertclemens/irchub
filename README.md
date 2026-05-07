# irchub

A hub server for coordinating networks of IRC bots. irchub handles centralized key management, encrypted configuration distribution, bot provisioning, and inter-hub mesh networking — so your bots always have up-to-date credentials and settings without manual intervention.

> **Companion project:** irchub is designed to work with [ircbot](https://github.com/robertclemens/ircbot/) — a C-based IRC bot that connects to irchub for secure configuration sync, op coordination, and inter-bot communication. You need both projects to run a complete setup.

## Overview

irchub sits between your IRC bots and your admin console. Each [ircbot](https://github.com/robertclemens/ircbot/) instance authenticates to the hub using a Curve25519 keypair. The hub distributes encrypted configuration (channels, admin masks, oper credentials, passwords) to all connected bots and keeps everything synchronized across multiple hub instances via a peer mesh.

```
hub_admin ──► irchub ──► ircbot A
                    └──► ircbot B
                    └──► irchub (peer) ──► ircbot C
```

**Key capabilities:**

- **Bot provisioning** — generate Curve25519 keypairs and deliver credentials to bots via IRC
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
| `keygen` | Curve25519 keypair generator |
| `hub_decrypt` | Decrypt and inspect config file |
| `hub_encrypt` | Re-encrypt a config file |

Built binaries are placed in `bin/`. Install them wherever suits your setup — the examples below assume the binaries are on your `PATH` or you are running from the directory containing them.

## Companion Project: ircbot

irchub is the hub — [ircbot](https://github.com/robertclemens/ircbot/) is the bot. The two projects are built to work together:

- **[ircbot](https://github.com/robertclemens/ircbot/)** connects to irchub on startup, authenticates with its Curve25519 keypair, and receives its full configuration (channels to join, passwords, admin masks) automatically.
- When a bot's config changes (new channel, password rotation, rekey), the hub pushes the update to all connected bots in real time.
- Bots request op grants through the hub, which coordinates across the mesh so any bot can grant ops to any other bot regardless of which hub they are connected to.
- Commands to the bot are authenticated using time-based hashes, and the hub distributes the shared secret needed to verify them.

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

Run from the directory where irchub will store its files (config, PID, log, and password files are all created relative to the working directory):

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
| **Hub Keypair** | Choose `1` to generate a new Curve25519 keypair inline, or `2` to load an existing `.b64` file |
| **Admin Password** | Password required by `hub_admin` to connect (hidden, confirmed twice) |

Setup writes the encrypted config file (`.irchub.cnf`) and exits. The hub does not start automatically.

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

The admin console connects to a running hub. It requires the hub's public key (PEM) for the encrypted handshake:

```bash
./hub_admin <hub-ip> <hub-port> <hub_public.b64>
```

To obtain the public key from a running hub, connect with `hub_admin`, go to **Manage Peer Config → Export Public Key**, and save the file.

### Admin Menu

```
IRC HUB ADMIN CONSOLE

  1. Manage Bots
  2. Manage Peer Connections
  3. Manage Peer Config
  4. Admin Commands
  5. Exit
```

### Adding a Bot

1. **Manage Bots → Add Bot**
2. Enter the bot's IRC nickname
3. The hub generates a Curve25519 keypair and UUID
4. Choose how to distribute the private key:
   - **Export to file** — saves `bot_<nick>_priv_key.b64`
   - **Show private key** — prints the base64 key to the terminal
   - **Show IRC commands** — prints the `/msg` commands to paste into IRC

The IRC commands look like:
```
/msg <botnick> <hash> sethubkey <88-char-base64-Curve25519-key>
/msg <botnick> <hash> setuuid <uuid>
/msg <botnick> <hash> +hub <hub_ip>:<hub_port>
```

Once the bot receives all parts it will connect to the hub automatically.

### Rekeying a Bot

**Manage Bots → Rekey Bot** generates a new keypair for a bot. If the bot is currently connected, the hub pushes the new key automatically and the bot reconnects. If offline, the same three-option distribution menu appears.

## Peer Mesh

Multiple hub instances can be linked to share configuration and bot state. Add a peer from **Manage Peer Connections → Add Peer**. Provide the peer's IP, port, UUID, and optional friendly name.

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
| Bind IP | Manage Peer Config → Set Bind IP |
| Bind Port | Manage Peer Config → Set Bind Port |
| Hub Name | Manage Peer Config → Set Hub Name |
| Log Level | Manage Peer Config → Set Log Level (0–4) |
| Log Size Limit | Manage Peer Config → Set Log Size Limit |
| IP Allowlist | Manage Peer Config → Manage IP Allowlist |
| IP Denylist | Manage Peer Config → Manage IP Denylist |
| Tombstone Purge | Manage Peer Config → Purge Tombstones |
| Auto Purge Schedule | Manage Peer Config → Configure Automatic Purge |
| Admin Password | Admin Commands → Change Admin Password |
| Bot Password | Admin Commands → Change Bot Password |
| Admin Masks | Admin Commands → Manage Admin Masks |
| Oper Masks | Admin Commands → Manage Oper Masks |
| Channels | Admin Commands → Manage Channels |

## Utilities

### Decrypt config (inspection / debugging)

```bash
./hub_decrypt [config-file]
```

Prompts for the config password and prints the plaintext config. Defaults to `.irchub.cnf` if no file is specified.

### Encrypt config

```bash
./hub_encrypt <plaintext-file> <output-file>
```

Re-encrypts a plaintext config file. Useful for migrating or restoring configs.

### Generate keypair

```bash
./keygen [private-key-out] [public-key-out]
```

Generates a Curve25519 keypair (Ed25519 + X25519). Defaults to `hub_private.b64` and `hub_public.b64`. Useful if you want to pre-generate a key before running `-setup` with option 2.

## Security Notes

- The config password is never passed on the command line or stored in an environment variable. It is read from `.irchub.pass` (if present) or prompted on stdin at startup.
- `.irchub.pass` is AES-256-GCM encrypted and machine-bound — it cannot be decrypted on a different host. The file must be owned by the current user with permissions `0600`; any deviation is rejected and irchub falls back to the stdin prompt.
- All bot-to-hub communication is encrypted with AES-256-GCM using per-session keys negotiated via Curve25519 (sealed-box).
- Failed authentication attempts are tracked per IP. After 3 failures the IP is blocked for 5 minutes; the failure counter resets after 1 hour. These thresholds are compile-time constants (`MAX_FAILED_AUTH_ATTEMPTS`, `FAILED_AUTH_BLOCK_DURATION`, `FAILED_AUTH_RESET_TIME` in `hub.h`) — adjust and rebuild to change them. Specific IPs and ranges can be permanently allowed or blocked at runtime via **Manage Peer Config → Manage IP Allowlist / Manage IP Denylist** in `hub_admin` (supports CIDR notation).
- Each IP is limited to 5 simultaneous connections (`MAX_CONNECTIONS_PER_IP` in `hub.h` — compile-time constant).
- Private key material is wiped from memory (`secure_wipe`) as soon as it is no longer needed.

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

# Connect admin console (needs hub's public key)
#./hub_admin <hub ip> <hub port> <public key b64>
./hub_admin 127.0.0.1 6697 hub_public.b64

# View logs (if logging has been turned on)
tail -f .irchub.log

# Inspect config (debug)
./hub_decrypt
```
