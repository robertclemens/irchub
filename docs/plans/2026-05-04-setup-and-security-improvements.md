# Setup & Security Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove password from command line (use `HUB_PASS` env var), fix the `-setup` interactive flow (bind IP hang, inline keypair generation, admin password confirm), replace bot key auto-export with a choice menu, remove the broken `-d` daemonize flag, and silence the linker cross-arch warnings.

**Architecture:** Focused in-place edits to four files (`hub.h`, `hub_main.c`, `hub_admin.c`, `run_hub.sh`) plus `Makefile` and `keygen.c`. No new files, no structural refactoring. The design doc is at `docs/plans/2026-05-04-setup-and-security-improvements-design.md`.

**Tech Stack:** C11, GCC, OpenSSL (EVP API), POSIX termios, GNU Make.

---

## Task 1: Makefile — Remove bad linker paths and update stale usage strings

**Files:**
- Modify: `Makefile`

This silences the `skipping incompatible /usr/lib/libgcc_s.so.1` warnings. The cause is the Makefile explicitly adding `/usr/lib` to the linker search path — on multiarch systems `/usr/lib` holds 32-bit objects, so the linker tries them, rejects them, then finds the right ones via its own default paths. Removing the explicit `-L` flags lets the linker use its defaults without the noise.

**Step 1: Change `LDFLAGS` base line**

In `Makefile` line 56, change:
```makefile
LDFLAGS = -L/usr/lib -L/usr/local/lib
```
to:
```makefile
LDFLAGS =
```

**Step 2: Update the `valgrind` target**

Find the valgrind target (around line 305). Change:
```makefile
          $(HUB_TARGET) test_password &
```
to:
```makefile
          $(HUB_TARGET) &
```
And add a note about the env var by adding this line just above the valgrind command:
```makefile
	@echo "Note: set HUB_PASS before running the hub binary"
```

**Step 3: Update the `install` target help text**

Find these lines in the install target (around line 272):
```makefile
	@echo "  2. Run setup: $(BINDIR)/irchub <password> -setup"
	@echo "  3. Start hub: $(BINDIR)/irchub <password>"
```
Change to:
```makefile
	@echo "  2. Run setup: $(BINDIR)/irchub -setup"
	@echo "  3. Set env and start: export HUB_PASS=<password> && $(BINDIR)/irchub"
```

**Step 4: Update the `help` target usage examples**

Find these lines in the help target (around line 378):
```makefile
	@echo "  ./bin/irchub mypass -setup          # Initial setup"
	@echo "  ./bin/irchub mypass                 # Run hub"
```
Change to:
```makefile
	@echo "  ./bin/irchub -setup                          # Initial setup"
	@echo "  export HUB_PASS=mypass && ./bin/irchub       # Run hub"
```

**Step 5: Update the Makefile's keygen.c recipe string**

In the `keygen.c:` recipe (around line 241), find:
```makefile
	@echo '    printf("  ./bin/irchub <password> -setup\\n");' >> keygen.c
```
Change to:
```makefile
	@echo '    printf("  ./bin/irchub -setup\\n");' >> keygen.c
```

**Step 6: Build and verify no linker warnings**

```bash
make clean && make
```
Expected: build succeeds, NO `skipping incompatible` lines in output.

**Step 7: Commit**

```bash
git add Makefile
git commit -m "fix: Remove explicit -L/usr/lib linker paths to silence multiarch warnings"
```

---

## Task 2: `hub.h` — Add `CONFIG_PASS_ENV_VAR`

**Files:**
- Modify: `hub.h`

**Step 1: Add the define**

After line 41 (`#define HUB_PID_FILE ".irchub.pid"`), add:
```c
#define CONFIG_PASS_ENV_VAR "HUB_PASS"
```

**Step 2: Build to verify no regressions**

```bash
make
```
Expected: clean build, no new warnings.

**Step 3: Commit**

```bash
git add hub.h
git commit -m "feat: Add CONFIG_PASS_ENV_VAR define for HUB_PASS environment variable"
```

---

## Task 3: `hub_main.c` — Remove `daemonize()` and the `-d` flag

**Files:**
- Modify: `hub_main.c`

**Step 1: Delete the `daemonize()` function**

Remove lines 441–466 (the entire `void daemonize()` function body):
```c
void daemonize() {
    pid_t pid = fork();
    ...
    if (x > 2) close(x);
    }
}
```

**Step 2: Remove `daemon_mode` variable and all code that references it**

In `main()`, remove:
```c
    bool daemon_mode = false;
    for(int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) daemon_mode = true;
    }
```

Remove:
```c
    log_fp = fopen(HUB_LOG_FILE, "a");
    if (daemon_mode) {
        printf("Starting in daemon mode...\n");
        daemonize();
    }
```
Keep just:
```c
    log_fp = fopen(HUB_LOG_FILE, "a");
```

**Step 3: Build to verify**

```bash
make
```
Expected: clean build. Any `unused variable` warning means a reference was missed — search and remove it.

**Step 4: Commit**

```bash
git add hub_main.c
git commit -m "fix: Remove daemonize() and -d flag (not supported on target systems)"
```

---

## Task 4: `hub_main.c` — Rework `main()`: env-var password, full setup flow rewrite

**Files:**
- Modify: `hub_main.c`

This is the largest task. It replaces the current argument-based password with `getenv()` for normal mode, and rewrites the entire `-setup` interactive flow.

**Step 1: Add `<termios.h>` include**

Add to the include block at the top of `hub_main.c`:
```c
#include <termios.h>
```

**Step 2: Add `read_pass_hidden()` helper — place it before `main()`**

```c
static void read_pass_hidden(const char *prompt, char *buf, size_t len) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(buf, (int)len, stdin)) buf[0] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    buf[strcspn(buf, "\n")] = 0;
}
```

**Step 3: Rewrite `main()` argument parsing block**

Replace the current `main()` opening (from `if (argc < 2)` through the `snprintf(state.config_pass...` line) with:

```c
int main(int argc, char *argv[]) {
    bool setup_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-setup") == 0) setup_mode = true;
    }

    hub_state_t state;
    memset(&state, 0, sizeof(state));
    state.running = true;
    g_state = &state;
    state.log_level = LOG_INFO;
    state.log_max_size = HUB_LOG_FILE_SIZE;
```

**Step 4: Replace the entire `-setup` block**

Remove the old `if (argc >= 3 && strcmp(argv[2], "-setup") == 0) { ... }` block and replace with:

```c
    if (setup_mode) {
        int ch;

        printf("--- Setup ---\n");

        printf("Port: ");
        if (scanf("%d", &state.port) != 1) return 1;
        while ((ch = getchar()) != '\n' && ch != EOF);  /* consume newline */

        printf("Bind IP (default 0.0.0.0): ");
        fflush(stdout);
        char bind_buf[65] = "";
        if (fgets(bind_buf, sizeof(bind_buf), stdin)) {
            bind_buf[strcspn(bind_buf, "\n")] = 0;
        }
        if (bind_buf[0] == 0) {
            snprintf(state.bind_ip, sizeof(state.bind_ip), "0.0.0.0");
        } else {
            snprintf(state.bind_ip, sizeof(state.bind_ip), "%s", bind_buf);
        }

        printf("Friendly Name: ");
        if (scanf("%63s", state.hub_friendly_name) != 1) return 1;
        state.hub_friendly_name[sizeof(state.hub_friendly_name) - 1] = 0;
        while ((ch = getchar()) != '\n' && ch != EOF);  /* consume newline */

        generate_uuid_v4(state.hub_uuid, sizeof(state.hub_uuid));
        printf("Generated UUID: %s\n", state.hub_uuid);

        read_pass_hidden("Config Password: ", state.config_pass, sizeof(state.config_pass));

        printf("\nHub Keypair:\n");
        printf("  1. Generate new keypair\n");
        printf("  2. Use existing key file\n");
        printf("Choice: ");
        fflush(stdout);
        int kp_choice = 0;
        if (scanf("%d", &kp_choice) != 1) kp_choice = 2;
        while ((ch = getchar()) != '\n' && ch != EOF);  /* consume newline */

        if (kp_choice == 1) {
            char *priv_pem = NULL, *pub_pem = NULL;
            printf("[*] Generating RSA-2048 keypair...\n");
            if (!hub_crypto_generate_keypair(&priv_pem, &pub_pem)) {
                printf("Key generation failed.\n");
                return 1;
            }
            state.private_key_pem = priv_pem;
            state.priv_key = load_private_key_from_memory(priv_pem);
            free(pub_pem);
            if (!state.priv_key) {
                printf("Failed to load generated key.\n");
                secure_wipe(priv_pem, strlen(priv_pem));
                free(priv_pem);
                return 1;
            }
            printf("[+] Keypair generated.\n");
        } else {
            printf("Private Key File Path: ");
            fflush(stdout);
            char kp_path[256] = "";
            if (!fgets(kp_path, sizeof(kp_path), stdin)) {
                printf("Read error.\n");
                return 1;
            }
            kp_path[strcspn(kp_path, "\n")] = 0;

            FILE *f = fopen(kp_path, "rb");
            if (!f) {
                printf("Key file not found.\n");
                return 1;
            }
            fseek(f, 0, SEEK_END);
            long s = ftell(f);
            fseek(f, 0, SEEK_SET);
            state.private_key_pem = malloc(s + 1);
            if (!state.private_key_pem || fread(state.private_key_pem, 1, s, f) != (size_t)s) {
                printf("Error reading key file.\n");
                if (state.private_key_pem) free(state.private_key_pem);
                fclose(f);
                return 1;
            }
            state.private_key_pem[s] = 0;
            fclose(f);
            state.priv_key = load_private_key_from_memory(state.private_key_pem);
            if (!state.priv_key) {
                printf("Failed to load private key.\n");
                secure_wipe(state.private_key_pem, strlen(state.private_key_pem));
                free(state.private_key_pem);
                return 1;
            }
        }

        char admin_pass1[MAX_PASS], admin_pass2[MAX_PASS];
        do {
            read_pass_hidden("Admin Password: ", admin_pass1, sizeof(admin_pass1));
            read_pass_hidden("Confirm Admin Password: ", admin_pass2, sizeof(admin_pass2));
            if (strcmp(admin_pass1, admin_pass2) != 0) {
                printf("Passwords do not match. Try again.\n");
            }
        } while (strcmp(admin_pass1, admin_pass2) != 0);
        snprintf(state.admin_password, sizeof(state.admin_password), "%s", admin_pass1);
        secure_wipe(admin_pass1, sizeof(admin_pass1));
        secure_wipe(admin_pass2, sizeof(admin_pass2));

        hub_config_write(&state);
        printf("Done.\n");

        if (state.priv_key) EVP_PKEY_free(state.priv_key);
        if (state.private_key_pem) {
            secure_wipe(state.private_key_pem, strlen(state.private_key_pem));
            free(state.private_key_pem);
        }
        return 0;
    }
```

**Step 5: Replace the normal-mode password source**

Immediately after the `if (setup_mode) { ... return 0; }` block, add:

```c
    const char *env_pass = getenv(CONFIG_PASS_ENV_VAR);
    if (!env_pass || !env_pass[0]) {
        fprintf(stderr, "Error: %s environment variable is not set.\n", CONFIG_PASS_ENV_VAR);
        fprintf(stderr, "Set it before starting: export %s=<password>\n", CONFIG_PASS_ENV_VAR);
        return 1;
    }
    snprintf(state.config_pass, sizeof(state.config_pass), "%s", env_pass);
```

Remove the old `snprintf(state.config_pass, sizeof(state.config_pass), "%s", argv[1]);` line if it still exists.

**Step 6: Update `Usage` string (if any remains)**

Search for any remaining `Usage:` string in `main()`. Update to:
```c
        fprintf(stderr, "Usage: ./irchub [-setup]\n");
        fprintf(stderr, "  Normal mode: set %s env var before running\n", CONFIG_PASS_ENV_VAR);
```
(Only if a usage print still exists — after the rewrite it may not be needed.)

**Step 7: Build and verify**

```bash
make
```
Expected: clean build, zero warnings. If you see `unused variable 'argc'` that means argv scanning was removed — add `(void)argc;` or keep the loop. If you see format/truncation warnings, verify the `snprintf` size arguments match the destination buffer.

**Step 8: Commit**

```bash
git add hub_main.c
git commit -m "feat: Use HUB_PASS env var for password; rewrite -setup interactive flow"
```

---

## Task 5: `hub_admin.c` — `bot_add()`: replace auto-export with key distribution menu

**Files:**
- Modify: `hub_admin.c:245-330` (`bot_add()`)

**Step 1: Locate the block to replace**

Inside `bot_add()`, find the section after `uuid` is extracted and printed. Currently it:
1. Prints IRC sethubkey commands
2. Auto-saves to `bot_<nick>_priv_key.b64`

Replace the entire key-distribution block (from `printf("Private key: %zu chars...")` through the `[Backup saved: ...]` printf, inclusive) with:

```c
            printf("\nKey Distribution:\n");
            printf("  1. Export to file\n");
            printf("  2. Show private key (base64)\n");
            printf("  3. Show IRC sethubkey commands\n\n");

            char kd_buf[10];
            get_input("Choice: ", kd_buf, sizeof(kd_buf));
            int kd_choice = atoi(kd_buf);

            switch (kd_choice) {
                case 1: {
                    char fname[128];
                    snprintf(fname, sizeof(fname), "bot_%s_priv_key.b64", nick);
                    FILE *kf = fopen(fname, "w");
                    if (kf) {
                        fprintf(kf, "%s\n", priv_key);
                        fclose(kf);
                        printf("[Saved: %s]\n", fname);
                    } else {
                        printf("Error: could not create file.\n");
                    }
                    break;
                }
                case 2:
                    printf("\nPrivate Key (base64):\n%s\n", priv_key);
                    break;
                case 3: {
                    size_t key_len = strlen(priv_key);
                    int total_parts = (int)((key_len + 249) / 250);
                    printf("Private key: %zu chars, %d parts\n\n", key_len, total_parts);
                    printf("COPY AND PASTE THESE COMMANDS:\n");
                    printf("===================================================\n\n");
                    for (int i = 0; i < total_parts; i++) {
                        size_t start = (size_t)i * 250;
                        size_t clen = (start + 250 > key_len) ? (key_len - start) : 250;
                        char chunk[260];
                        memset(chunk, 0, sizeof(chunk));
                        memcpy(chunk, priv_key + start, clen);
                        chunk[clen] = '\0';
                        printf("/msg %s <hash> sethubkey %d/%d:%s\n",
                               nick, i + 1, total_parts, chunk);
                    }
                    printf("\n/msg %s <hash> setuuid %s\n", nick, uuid);
                    printf("/msg %s <hash> +hub <hub_ip>:<hub_port>\n\n", nick);
                    printf("===================================================\n");
                    break;
                }
                default:
                    printf("Invalid choice.\n");
                    break;
            }
```

**Step 2: Build and verify**

```bash
make
```
Expected: clean build, no warnings.

**Step 3: Commit**

```bash
git add hub_admin.c
git commit -m "feat: Replace bot_add() auto key export with 3-option distribution menu"
```

---

## Task 6: `hub_admin.c` — `bot_rekey()`: same menu for the manual-update path

**Files:**
- Modify: `hub_admin.c:354-452` (`bot_rekey()`)

The auto-update path (`AUTO-UPDATED`) is untouched. Only the `else` branch (bot was not connected, manual update required) changes.

**Step 1: Locate the else branch**

Find the block starting with:
```c
                } else {
                    // Manual update required (bot was not connected)
                    size_t key_len = strlen(priv_key);
```

Replace everything in that `else` block from `size_t key_len = ...` through the `[New key backup: ...]` printf (inclusive) with:

```c
                } else {
                    printf("Bot was NOT connected - manual update required.\n\n");

                    printf("\nKey Distribution:\n");
                    printf("  1. Export to file\n");
                    printf("  2. Show private key (base64)\n");
                    printf("  3. Show IRC sethubkey commands\n\n");

                    char kd_buf[10];
                    get_input("Choice: ", kd_buf, sizeof(kd_buf));
                    int kd_choice = atoi(kd_buf);

                    switch (kd_choice) {
                        case 1: {
                            char fname[128];
                            snprintf(fname, sizeof(fname), "bot_%s_priv_key_REKEY.b64", nick);
                            FILE *kf = fopen(fname, "w");
                            if (kf) {
                                fprintf(kf, "%s\n", priv_key);
                                fclose(kf);
                                printf("[Saved: %s]\n", fname);
                            } else {
                                printf("Error: could not create file.\n");
                            }
                            break;
                        }
                        case 2:
                            printf("\nPrivate Key (base64):\n%s\n", priv_key);
                            break;
                        case 3: {
                            size_t key_len = strlen(priv_key);
                            int total_parts = (int)((key_len + 249) / 250);
                            printf("Private key: %zu chars, %d parts\n\n", key_len, total_parts);
                            printf("COPY AND PASTE THESE COMMANDS:\n");
                            printf("===================================================\n\n");
                            for (int i = 0; i < total_parts; i++) {
                                size_t start = (size_t)i * 250;
                                size_t clen = (start + 250 > key_len) ? (key_len - start) : 250;
                                char chunk[260];
                                memset(chunk, 0, sizeof(chunk));
                                memcpy(chunk, priv_key + start, clen);
                                chunk[clen] = '\0';
                                printf("/msg %s <hash> sethubkey %d/%d:%s\n",
                                       nick, i + 1, total_parts, chunk);
                            }
                            printf("\n/msg %s <hash> +hub <hub_ip>:<hub_port>\n\n", nick);
                            printf("===================================================\n");
                            break;
                        }
                        default:
                            printf("Invalid choice.\n");
                            break;
                    }
```

Note: the rekey variant omits the `setuuid` command (the bot already has its UUID; only the key changes) but adds the `+hub` reconnect command.

**Step 2: Build and verify**

```bash
make
```
Expected: clean build.

**Step 3: Commit**

```bash
git add hub_admin.c
git commit -m "feat: Replace bot_rekey() auto key export with 3-option distribution menu"
```

---

## Task 7: `run_hub.sh` and `keygen.c` — Update to use `HUB_PASS` env var

**Files:**
- Modify: `run_hub.sh`
- Modify: `keygen.c`

**Step 1: Rewrite `run_hub.sh`**

Replace the entire file content with:

```bash
#!/bin/bash

#########################################################################################
# Set your variables
export HUB_PASS="configpasswordhere"
PID_FILE=".irchub.pid"

# HUB_PASS is the config encryption password (read by irchub via getenv)
# PID_FILE must match hub.h #define HUB_PID_FILE
#########################################################################################

# Navigate to the hub's directory
cd "$(dirname "$0")"

# Check if the PID file exists
if [ -e "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "Hub is already running (PID: $PID). Exiting."
        exit 1
    else
        echo "Found stale PID file. Removing."
        rm -f "$PID_FILE"
    fi
fi

./irchub &

echo "Hub started (PID: $!)"
```

Key changes: `CONFIG_PASS` removed, `export HUB_PASS=...` added, `./irchub` invoked without any password argument.

**Step 2: Update stale usage message in `keygen.c`**

Find line:
```c
    printf("  ./bin/irchub <password> -setup\n");
```
Change to:
```c
    printf("  ./bin/irchub -setup\n");
```

**Step 3: Build final check**

```bash
make clean && make
```
Expected: full clean build, zero `skipping incompatible` linker warnings, zero compiler warnings.

**Step 4: Commit**

```bash
git add run_hub.sh keygen.c
git commit -m "fix: Use HUB_PASS env var in run_hub.sh; update keygen usage message"
```

---

## Task 8: Smoke test the full flow

No automated test framework is set up for this C codebase, so manually verify the critical paths.

**Step 1: Verify normal mode fails cleanly without env var**

```bash
./bin/irchub
```
Expected output (exits immediately):
```
Error: HUB_PASS environment variable is not set.
Set it before starting: export HUB_PASS=<password>
```

**Step 2: Verify `-setup` runs interactively**

```bash
./bin/irchub -setup
```
Expected: prompts for Port, Bind IP (hitting Enter defaults to `0.0.0.0`), Friendly Name, Config Password (hidden), keypair menu (1 or 2), Admin Password + confirm. Config file written on completion.

**Step 3: Verify normal mode starts with env var**

```bash
export HUB_PASS="configpasswordhere"
./bin/irchub
```
Expected: hub starts, writes PID file, begins listening.

**Step 4: Verify hub_admin bot_add menu**

Connect hub_admin, navigate to Manage Bots → Add Bot. After bot is created, verify the three-option menu appears and each option works correctly.

**Step 5: Final commit if any last-minute fixes were made**

```bash
git add -p   # stage only intended changes
git commit -m "fix: Address smoke test findings"
```
