/* The SSH admin console: what the core (hub_console_core.c, main thread) and
 * the console thread (hub_console.c + hub_console_ui.c) share.  See
 * docs/console.md.  Nothing in here touches hub_state_t: the two threads meet
 * only on socketpairs and on the small published snapshot below. */
#ifndef HUB_CONSOLE_H
#define HUB_CONSOLE_H

#include "hub.h"

/* Most unauthenticated SSH connections from one address at a time. */
#define CONSOLE_MAX_PREAUTH_PER_IP 2
/* Largest control / session frame either side accepts. */
#define CONSOLE_FRAME_MAX (4 * 1024 * 1024)

/* ---- Published snapshot (mutex-protected, hub_console.c) ---------------
 * The core publishes; the console thread reads a copy when it needs one.
 * These are the only data the two threads share. */
typedef struct {
  char          name[CONSOLE_NAME_MAX];
  unsigned char ed_pub[32];
} console_cred_t;

void console_publish_creds(const console_cred_t *creds, int n);
void console_publish_hostkey(const unsigned char seed[32],
                             const unsigned char pub[32]);
void console_publish_hubname(const char *name);

/* Start / stop the console thread.  ctl_fd is the thread's end of the
 * control socketpair; the thread owns it from here on. */
bool console_thread_start(int ctl_fd);
void console_thread_stop(void);

/* ---- Framing helpers (both threads) ------------------------------------ */
/* Write one control frame (len(4) || text) on a blocking-tolerant fd; false
 * when the peer is gone. */
bool console_ctl_write(int fd, const char *text);

/* "SHA256:<base64 without padding>" of an ssh-ed25519 public key. */
void console_ssh_fingerprint(const unsigned char pub[32], char *out,
                             size_t out_size);

/* ---- Text utilities shared by the console files ------------------------ */
/* Length of the valid UTF-8 sequence at p (n bytes available), 0 if none. */
size_t console_utf8_len(const unsigned char *p, size_t n);
/* docs/console.md §5: control bytes dropped (TAB -> space), invalid UTF-8
 * -> '?', C1 controls dropped.  Returns the output length (NUL-terminated). */
size_t console_sanitize(const char *in, size_t n, char *out, size_t cap);

#endif
