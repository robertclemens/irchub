# irchub

A hub server for coordinating networks of IRC bots. irchub handles centralized key management, encrypted configuration distribution, bot provisioning, and inter-hub mesh networking — so your bots always have up-to-date credentials and settings without manual intervention.

## Overview

irchub sits between your IRC bots and your admin console. Each bot authenticates to the hub using an RSA-2048 keypair. The hub distributes encrypted configuration (channels, admin masks, oper credentials, passwords) to all connected bots and keeps everything synchronized across multiple hub instances via a peer mesh.

```
hub_admin ──► irchub ──► Bot A
                    └──► Bot B
                    └──► irchub (peer) ──► Bot C
```

**Key capabilities:**

- **Bot provisioning** — generate RSA keypairs and deliver credentials to bots via IRC
- **Encrypted config sync** — AES-256-GCM encrypted configuration pushed to all bots on connect and periodically
- **Peer mesh** — multiple hub instances synchronize state; leader election prevents duplicate operations
- **Admin console** — interactive TUI (`hub_admin`) for managing bots, channels, masks, and opers
- **IP access control** — allowlist/denylist with CIDR support
- **Rate limiting** — per-IP connection limits and failed-auth blocking
- **Tombstone purging** — automatic cleanup of deleted config entries with configurable retention

## Components

| Binary | Purpose |
|--------|---------|
| `bin/irchub` | Hub server |
| `bin/hub_admin` | Interactive admin console |
| `bin/keygen` | RSA-2048 keypair generator |
| `bin/hub_decrypt` | Decrypt and inspect config file |
| `bin/hub_encrypt` | Re-encrypt a config file |

## Dependencies

| Dependency | Minimum | Notes |
|------------|---------|-------|
| GCC | 7+ | C11 support required (`-std=c11`) |
| OpenSSL | 1.1.1+ | `libssl`, `libcrypto` — EVP API required |
| POSIX | — | Linux/Unix only (uses `termios`, `flock`, `POSIX sockets`) |
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

```bash
./bin/irchub -setup
```

You will be prompted for:

| Prompt | Description |
|--------|-------------|
| **Port** | TCP port the hub listens on (e.g. `6697`) |
| **Bind IP** | Interface to bind to — press Enter to default to `0.0.0.0` (all interfaces) |
| **Friendly Name** | Human-readable name for this hub instance |
| **Config Password** | Password used to encrypt the config file (hidden input) |
| **Hub Keypair** | Choose `1` to generate a new RSA-2048 keypair inline, or `2` to load an existing PEM file |
| **Admin Password** | Password required by `hub_admin` to connect (hidden, confirmed twice) |

Setup writes the encrypted config file (`.irchub.cnf`) and exits. The hub does not start automatically.

### 2. Configure `run_hub.sh`

Edit `run_hub.sh` and set `HUB_PASS` to the config password you chose during setup:

```bash
export HUB_PASS="your-config-password-here"
```

### 3. Start the hub

```bash
./run_hub.sh
```

The hub starts in the background. Logs are written to `.irchub.log`.

To stop the hub:

```bash
kill $(cat .irchub.pid)
```

## Admin Console

The admin console connects to a running hub. It requires the hub's public key (PEM) for the encrypted handshake:

```bash
./bin/hub_admin <hub-ip> <hub-port> <hub_public.pem>
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
3. The hub generates an RSA keypair and UUID
4. Choose how to distribute the private key:
   - **Export to file** — saves `bot_<nick>_priv_key.b64`
   - **Show private key** — prints the base64 key to the terminal
   - **Show IRC commands** — prints the `/msg` commands to paste into IRC

The IRC commands look like:
```
/msg <botnick> <hash> sethubkey 1/3:<chunk>
/msg <botnick> <hash> sethubkey 2/3:<chunk>
/msg <botnick> <hash> sethubkey 3/3:<chunk>
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
./bin/hub_decrypt [config-file]
```

Prompts for the config password and prints the plaintext config. Defaults to `.irchub.cnf` if no file is specified.

### Encrypt config

```bash
./bin/hub_encrypt <plaintext-file> <output-file>
```

Re-encrypts a plaintext config file. Useful for migrating or restoring configs.

### Generate keypair

```bash
./bin/keygen [private-key-out] [public-key-out]
```

Generates an RSA-2048 keypair. Defaults to `hub_private.pem` and `hub_public.pem`. Useful if you want to pre-generate a key before running `-setup` with option 2.

## Security Notes

- The config password is never passed on the command line. It is set via the `HUB_PASS` environment variable (normal mode) or entered interactively (setup mode).
- All bot-to-hub communication is encrypted with AES-256-GCM using per-session keys negotiated via RSA-2048.
- Failed authentication attempts are tracked per IP. After 3 failures, the IP is blocked for 5 minutes.
- Each IP is limited to 5 simultaneous connections.
- Private key material is wiped from memory (`secure_wipe`) as soon as it is no longer needed.

## Files

| File | Description |
|------|-------------|
| `.irchub.cnf` | Encrypted config file (created by `-setup`) |
| `.irchub.pid` | PID file (created on start, removed on stop) |
| `.irchub.log` | Log file (rotating, default 10 MB limit) |
| `run_hub.sh` | Startup script — set `HUB_PASS` here |

## Log Levels

Set via **Manage Peer Config → Set Log Level** in `hub_admin`:

| Level | Name | Output |
|-------|------|--------|
| 0 | NONE | No logging |
| 1 | ERROR | Errors only |
| 2 | WARNING | Errors + warnings |
| 3 | INFO | Default — errors, warnings, info |
| 4 | DEBUG | Everything |

## Quick Reference

```bash
# Build
make

# First-time setup
./bin/irchub -setup

# Edit run_hub.sh, set HUB_PASS, then start
./run_hub.sh

# Connect admin console (needs hub's public key)
./bin/hub_admin 127.0.0.1 6697 hub_public.pem

# Stop hub
kill $(cat .irchub.pid)

# View logs
tail -f .irchub.log

# Inspect config (debug)
./bin/hub_decrypt
```
