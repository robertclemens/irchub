/* hub_update.c — the hub's own signed self-update, for the network upgrade.
 *
 * This is the hub-side twin of ircbot/utils.c's updater, and it exists for one
 * reason: a network upgrade that can move every bot but not the hubs leaves
 * the mesh permanently mixed.  The orchestration in hub_logic.c already treats
 * peer hubs and this hub as nodes of a run; what lives here is what a node
 * needs to actually *be* upgraded — fetch a signed manifest, pick the artifact
 * that fits this host, install it atomically and keep the old one so the run
 * can be rolled back.
 *
 * Trust model, identical to the bot's: the manifest is verified against the
 * pinned Ed25519 key in HUB_UPDATE_PUBKEY_B64 before a single field in it is
 * read, and each artifact against the SHA-256 the signed manifest gives.  An
 * empty pinned key disables updates entirely (fail-closed), and a hub built
 * without libcurl reports the feature unavailable rather than falling back to
 * anything.
 */
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#include "hub.h"

/* Close every descriptor above stderr before this process exec()s into the
 * upgrade script or the retained build.  None of the hub's sockets are
 * close-on-exec, so without this the replacement inherits the old listening
 * socket — and its own bind() on the same port fails ("Bind failed"), leaving
 * a hub that installed the new build but never comes back — plus every peer
 * and bot connection, which would stay open, half-alive, under the new
 * process.  (The Rust hub gets this for free: std opens sockets CLOEXEC.)
 * Nothing is logged after this point; the log file's fd is closed too. */
static void hub_update_close_fds_for_exec(void) {
  fflush(NULL); /* every stdio stream, the log included */
  long max = sysconf(_SC_OPEN_MAX);
  if (max < 0 || max > 65536) max = 65536;
  for (int fd = 3; fd < (int)max; fd++) close(fd);
}

#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

/* ---- Host capability probe (answered in CMD_UPGRADE_READY) --------------
 * Both answers describe the RUNNING binary, not the machine in the abstract:
 * a hub reports what it can be replaced with.  The arch comes from uname(2)
 * so it matches the manifest's `uname -m` spelling; the libc is decided at
 * compile time because the binary is already linked against one and musl
 * publishes no runtime identifier. */
void hub_update_host_arch(char *out, size_t out_size) {
  if (!out || out_size == 0) return;
  struct utsname u;
  if (uname(&u) == 0 && u.machine[0])
    snprintf(out, out_size, "%s", u.machine);
  else
    snprintf(out, out_size, "unknown");
}

void hub_update_host_libc(char *out, size_t out_size) {
  if (!out || out_size == 0) return;
#if defined(__GLIBC__)
  snprintf(out, out_size, "gnu");
#elif defined(__linux__)
  snprintf(out, out_size, "musl");
#else
  snprintf(out, out_size, "unknown");
#endif
}

const char *hub_update_host_variant(void) { return HUB_UPDATE_VARIANT; }

/* ---- Version comparison -------------------------------------------------
 * glibc strverscmp, carried here rather than linked so a hub on musl or an
 * older libc compares versions the same way every other node does. */
static int hub_strverscmp(const char *s1, const char *s2) {
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;
  unsigned char c1, c2;

  while ((c1 = *p1++) == (c2 = *p2++)) {
    if (c1 == '\0') return 0;
  }
  p1--;
  p2--;

  if (isdigit(c1) && isdigit(c2)) {
    int state = 0;
    while (1) {
      if (state == 0) {
        if (c1 > c2)
          state = 1;
        else if (c1 < c2)
          state = -1;
      }
      c1 = isdigit(*p1) ? *p1++ : 0;
      c2 = isdigit(*p2) ? *p2++ : 0;
      if (!c1 && !c2) break;
      if (c1 == 0 && c2 != 0) return -1;
      if (c1 != 0 && c2 == 0) return 1;
    }
    return state;
  }
  return (int)p1[0] - (int)p2[0];
}

/* Release manifests spell versions with a leading 'v' ("v2.3.0") while
 * HUB_VERSION does not ("2.4.0").  Compare them on the numeric part alone:
 * hub_strverscmp("v0.0.1", "2.4.0") would otherwise compare 'v' against '2' and
 * report a downgrade as an upgrade, which is exactly what the downgrade guard
 * exists to stop.  Mirrors updater_version_cmp in ircbot/utils.c. */
static const char *version_strip_v(const char *v) {
  if (!v) return "";
  return (*v == 'v' || *v == 'V') ? v + 1 : v;
}

int hub_update_version_cmp(const char *a, const char *b) {
  return hub_strverscmp(version_strip_v(a), version_strip_v(b));
}

static bool version_eq(const char *a, const char *b) {
  return strcasecmp(version_strip_v(a), version_strip_v(b)) == 0;
}

/* ---- Upgrade hand-off marker -------------------------------------------
 * exec() throws away everything the old process knew, so the upgrade id and
 * the version we were aiming at are left in a file for the new binary to
 * find.  It is read exactly once, by the peer-upgrade reporting path after
 * the restart, and removed there. */
bool hub_upgrade_marker_write(const char *upgrade_id, const char *target_ver,
                              const char *variant) {
  if (!upgrade_id || !target_ver || !variant) return false;
  int fd = open(HUB_UPGRADE_MARKER_FILE,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  char line[256];
  /* id|version|variant.  The variant is what makes a C<->Rust switch at the
   * same version checkable: without it the old build, restored by the
   * script's watchdog, would read the marker and report "ok". */
  int n = snprintf(line, sizeof(line), "%s|%s|%s\n", upgrade_id, target_ver,
                   variant);
  bool ok = (n > 0 && n < (int)sizeof(line) && write(fd, line, (size_t)n) == n);
  if (close(fd) != 0) ok = false;
  if (!ok) remove(HUB_UPGRADE_MARKER_FILE);
  return ok;
}

/* Read and consume the marker.  False for every ordinary start. */
bool hub_update_take_pending(char *id_out, size_t id_size, char *ver_out,
                             size_t ver_size, char *variant_out,
                             size_t variant_size) {
  if (!id_out || !ver_out || !variant_out || id_size == 0 || ver_size == 0 ||
      variant_size == 0)
    return false;
  id_out[0] = ver_out[0] = variant_out[0] = '\0';

  FILE *f = fopen(HUB_UPGRADE_MARKER_FILE, "r");
  if (!f) return false;
  char line[256] = "";
  bool got = (fgets(line, sizeof(line), f) != NULL);
  fclose(f);
  /* Consumed whatever it said: a marker we cannot parse must not be retried
   * on every reconnect for the rest of this process's life. */
  remove(HUB_UPGRADE_MARKER_FILE);
  if (!got) return false;

  /* A two-field marker (an older build wrote it) has no variant: "". */
  char id[64] = "", ver[64] = "", variant[16] = "";
  if (sscanf(line, "%63[^|\r\n]|%63[^|\r\n]|%15[^|\r\n]", id, ver,
             variant) < 2)
    return false;
  if (!id[0] || !ver[0]) return false;
  snprintf(id_out, id_size, "%s", id);
  snprintf(ver_out, ver_size, "%s", ver);
  snprintf(variant_out, variant_size, "%s", variant);
  return true;
}

/* ---- Rollback -----------------------------------------------------------
 * Put back the binary and config an upgrade retained, then restart onto them.
 * Used for CMD_UPGRADE_ABORT: by the time it arrives the new build is already
 * the running process, so undoing it means another exec. */
bool hub_update_rollback(hub_state_t *state, const char *reason) {
  if (!state || !state->executable_path[0]) return false;
  char prev_exe[PATH_MAX + 8], prev_cfg[PATH_MAX];
  if (snprintf(prev_exe, sizeof(prev_exe), "%s%s", state->executable_path,
               HUB_UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_exe) ||
      snprintf(prev_cfg, sizeof(prev_cfg), "%s%s", HUB_CONFIG_FILE,
               HUB_UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_cfg))
    return false;
  if (access(prev_exe, X_OK) != 0) {
    hub_log_error("[UPGRADE] Rollback requested (%s) but no retained binary\n",
            reason ? reason : "no reason given");
    return false;
  }

  hub_log_warning("[UPGRADE] Rolling back to the retained build: %s\n",
          reason ? reason : "the upgrade was aborted");
  /* Config first: if the restart races us, the old binary must not come up
   * against a config only the newer build understands. */
  if (access(prev_cfg, R_OK) == 0 && rename(prev_cfg, HUB_CONFIG_FILE) != 0)
    hub_log_error("[UPGRADE] Could not restore %s; keeping the current one\n",
            prev_cfg);
  if (rename(prev_exe, state->executable_path) != 0) {
    hub_log_error("[UPGRADE] Could not restore %s\n", prev_exe);
    return false;
  }
  remove(HUB_UPGRADE_MARKER_FILE);

  hub_config_write(state);
  if (state->pid_fd >= 0) close(state->pid_fd);
  remove(HUB_PID_FILE);
  sleep(1);
  hub_update_close_fds_for_exec();
  execl(state->executable_path, state->executable_path, (char *)NULL);
  exit(1); /* exec of the restored build failed; the log is already closed */
}

#ifdef HAVE_CURL

/* ---- Fetch --------------------------------------------------------------
 * Same libcurl usage as the bot's updater, including the two settings that
 * matter: peer and host verification stay on, always. */
typedef struct {
  char *buffer;
  size_t size;
} hub_http_response_t;

/* curl 7.85 replaced the bitmask protocol options with string ones and marked
 * the old pair deprecated; Rocky 8's 7.61 has only the bitmask.  Pick at
 * compile time so both build warning-free. */
#if LIBCURL_VERSION_NUM >= 0x075500
#define UPDATER_SET_PROTOCOLS(h)                                               \
  do {                                                                         \
    curl_easy_setopt((h), CURLOPT_PROTOCOLS_STR, "https,file");                \
    curl_easy_setopt((h), CURLOPT_REDIR_PROTOCOLS_STR, "https");               \
  } while (0)
#else
#define UPDATER_SET_PROTOCOLS(h)                                               \
  do {                                                                         \
    curl_easy_setopt((h), CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_FILE);\
    curl_easy_setopt((h), CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);           \
  } while (0)
#endif

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t realsize = size * nmemb;
  hub_http_response_t *mem = (hub_http_response_t *)userp;
  /* Bound the reply: a manifest is a few KB, and an unbounded realloc loop on
   * a hostile or broken server is a memory-exhaustion hole. */
  if (mem->size + realsize + 1 > HUB_UPDATE_MAX_MANIFEST) return 0;

  char *ptr = realloc(mem->buffer, mem->size + realsize + 1);
  if (!ptr) return 0;
  mem->buffer = ptr;
  memcpy(&mem->buffer[mem->size], contents, realsize);
  mem->size += realsize;
  mem->buffer[mem->size] = '\0';
  return realsize;
}

static size_t write_file_callback(void *ptr, size_t size, size_t nmemb,
                                  FILE *stream) {
  return fwrite(ptr, size, nmemb, stream);
}

/* A statically linked release binary carries the CA-bundle path of the distro
 * it was built on (Alpine: /etc/ssl/certs/ca-certificates.crt), which RHEL /
 * Rocky / Fedora do not have — every https fetch would then fail closed.  If
 * that compiled-in bundle is missing here, point curl at the first readable
 * bundle this host does have.  A distro-built (dynamic) libcurl's default is
 * right for its own host and is left alone.  Peer verification stays on
 * either way; this only chooses which trust store it uses. */
static void hub_update_set_ca(CURL *h) {
#if LIBCURL_VERSION_NUM >= 0x074600 /* 7.70: curl_version_info()->cainfo */
  static const char *const bundles[] = {
      "/etc/ssl/certs/ca-certificates.crt",               /* Debian/Ubuntu/Alpine */
      "/etc/pki/tls/certs/ca-bundle.crt",                 /* RHEL/Rocky/Fedora    */
      "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", /* RHEL (extracted)     */
      "/etc/ssl/ca-bundle.pem",                           /* openSUSE             */
      "/etc/ssl/cert.pem",                                /* Alpine/BSD           */
  };
  const curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
  if (vi && vi->age >= CURLVERSION_SEVENTH && vi->cainfo &&
      access(vi->cainfo, R_OK) == 0)
    return;
  for (size_t i = 0; i < sizeof(bundles) / sizeof(bundles[0]); i++) {
    if (access(bundles[i], R_OK) == 0) {
      curl_easy_setopt(h, CURLOPT_CAINFO, bundles[i]);
      return;
    }
  }
#else
  (void)h;
#endif
}

/* Manifest reads made from the event loop (a PREPARE answer, the hub_admin
 * release list) run on a short budget: the hub serves nothing while curl
 * blocks, and a peer link that misses its pings is a worse outcome than a
 * node answering "unable: manifest fetch failed".  0 = the full budget, for
 * COMMIT, which is about to restart the process anyway. */
static long g_fetch_quick = 0;

static void curl_common(CURL *h, const char *url) {
  curl_easy_setopt(h, CURLOPT_URL, url);
  curl_easy_setopt(h, CURLOPT_USERAGENT, "irchub-updater/1.0");
  curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, g_fetch_quick ? 5L : 30L);
  curl_easy_setopt(h, CURLOPT_TIMEOUT,
                   g_fetch_quick ? g_fetch_quick : HUB_UPDATE_FETCH_TIMEOUT);
  /* Fail-closed transport: a 404 page is not a manifest.  Without
   * FAILONERROR curl reports CURLE_OK for a 4xx/5xx and hands the error body
   * to the caller, so a missing release tree arrives as a signature failure
   * rather than a clean "not found".  The protocol allow-list keeps a
   * redirect from walking the updater onto any other scheme curl was built
   * with. */
  curl_easy_setopt(h, CURLOPT_FAILONERROR, 1L);
  UPDATER_SET_PROTOCOLS(h);
  hub_update_set_ca(h);
}

static bool fetch_url(const char *url, hub_http_response_t *response) {
  CURL *h = curl_easy_init();
  if (!h) return false;
  response->buffer = malloc(1);
  response->size = 0;
  if (!response->buffer) {
    curl_easy_cleanup(h);
    return false;
  }
  response->buffer[0] = '\0';
  curl_common(h, url);
  curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(h, CURLOPT_WRITEDATA, (void *)response);
  CURLcode res = curl_easy_perform(h);
  curl_easy_cleanup(h);
  return res == CURLE_OK;
}

static bool download_file(const char *url, const char *outfile) {
  CURL *h = curl_easy_init();
  if (!h) return false;
  /* 0600 from the start: no world-readable window on a file we are about to
   * unpack and run. */
  int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  FILE *fp = (fd >= 0) ? fdopen(fd, "wb") : NULL;
  if (!fp) {
    if (fd >= 0) close(fd);
    curl_easy_cleanup(h);
    return false;
  }
  curl_common(h, url);
  curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_file_callback);
  curl_easy_setopt(h, CURLOPT_WRITEDATA, fp);
  curl_easy_setopt(h, CURLOPT_MAXFILESIZE_LARGE,
                   (curl_off_t)HUB_UPDATE_MAX_ARCHIVE);
  CURLcode res = curl_easy_perform(h);
  curl_easy_cleanup(h);
  bool ok = (fclose(fp) == 0) && res == CURLE_OK;
  if (!ok) remove(outfile);
  return ok;
}

static bool verify_sha256(const char *filepath, const char *expected_hash) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    return false;
  }
  FILE *f = fopen(filepath, "rb");
  if (!f) {
    EVP_MD_CTX_free(ctx);
    return false;
  }
  unsigned char buf[4096];
  size_t n;
  bool ok = true;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    if (EVP_DigestUpdate(ctx, buf, n) != 1) {
      ok = false;
      break;
    }
  }
  if (ferror(f)) ok = false;
  fclose(f);
  if (ok) ok = (EVP_DigestFinal_ex(ctx, hash, &hash_len) == 1);
  EVP_MD_CTX_free(ctx);
  if (!ok || hash_len != 32) return false;

  char hex[65];
  for (unsigned i = 0; i < hash_len; i++)
    snprintf(hex + i * 2, 3, "%02x", hash[i]);
  return strcasecmp(hex, expected_hash) == 0;
}

/* ---- URL and filename gates --------------------------------------------
 * A non-empty IRCHUB_UPDATE_BASE overrides the compiled release base.  The
 * sandboxed testnet uses it to read a local irchub-releases tree over a
 * file:// URL with no outbound network.  When set, validate_url also accepts
 * URLs that begin with that base; the Ed25519 signature and the SHA-256 checks
 * stay fully active — only the github/https host allow-list is relaxed, and
 * only for this explicitly-configured base. */
static const char *hub_update_env_base(void) {
  const char *b = getenv("IRCHUB_UPDATE_BASE");
  return (b && b[0]) ? b : NULL;
}

/* The base a run is working against: what the driving hub named, else the
 * operator's env override, else the compiled-in root. */
static const char *effective_root(const char *base) {
  if (base && base[0]) return base;
  const char *e = hub_update_env_base();
  return e ? e : HUB_UPDATE_BASE;
}

static bool validate_url(const char *url) {
  if (!url) return false;
  /* Reject shell metacharacters regardless of source. */
  if (strpbrk(url, ";|&`$")) return false;
  const char *ebase = hub_update_env_base();
  if (ebase && strncmp(url, ebase, strlen(ebase)) == 0) return true;
  if (strncmp(url, "https://", 8) != 0) return false;
  return strstr(url, "github.com") != NULL ||
         strstr(url, "githubusercontent.com") != NULL;
}

/* Keep [A-Za-z0-9._-]; the result must end in ".tar.gz". */
static bool sanitize_filename(const char *input, char *out, size_t out_size) {
  if (!input || !out || out_size == 0) return false;
  size_t o = 0;
  for (const char *p = input; *p && o + 1 < out_size; p++) {
    if (isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')
      out[o++] = *p;
  }
  out[o] = '\0';
  size_t len = strlen(out);
  return len >= 8 && strcmp(out + len - 7, ".tar.gz") == 0;
}

/* ---- Manifest ----------------------------------------------------------- */

/* Fetch releases.txt and its detached signature and verify one against the
 * other before any field in the manifest is trusted. */
static char *fetch_verified_manifest(const char *base, const char **err) {
  *err = NULL;

  /* Pinned key, unless the local-source override is active AND a test key is
   * provided (sandbox only): IRCHUB_UPDATE_PUBKEY is honored solely when
   * IRCHUB_UPDATE_BASE is set, so production always uses the compiled key. */
  const char *pubkey_b64 = HUB_UPDATE_PUBKEY_B64;
  if (hub_update_env_base()) {
    const char *ep = getenv("IRCHUB_UPDATE_PUBKEY");
    if (ep && ep[0]) pubkey_b64 = ep;
  }
  if (pubkey_b64[0] == '\0') {
    *err = "hub updater disabled (no signing key configured)";
    return NULL;
  }

  int publen = 0;
  unsigned char *pub = base64_decode(pubkey_b64, &publen);
  if (!pub || publen != 32) {
    free(pub);
    *err = "configured update public key is malformed";
    return NULL;
  }

  char man_url[1024], sig_url[1024];
  if (snprintf(man_url, sizeof(man_url), "%s/releases.txt", base) >=
          (int)sizeof(man_url) ||
      snprintf(sig_url, sizeof(sig_url), "%s/releases.sig", base) >=
          (int)sizeof(sig_url)) {
    free(pub);
    *err = "release base URL too long";
    return NULL;
  }

  hub_http_response_t man = {NULL, 0};
  if (!fetch_url(man_url, &man)) {
    free(pub);
    free(man.buffer);
    *err = "failed to download release manifest";
    return NULL;
  }

  hub_http_response_t sig = {NULL, 0};
  if (!fetch_url(sig_url, &sig)) {
    free(pub);
    free(man.buffer);
    free(sig.buffer);
    *err = "failed to download release signature";
    return NULL;
  }

  int siglen = 0;
  unsigned char *sigbytes = base64_decode(sig.buffer, &siglen);
  bool ok = (sigbytes && siglen == 64 &&
             hub_crypto_ed25519_verify(pub, (const unsigned char *)man.buffer,
                                       man.size, sigbytes));
  free(pub);
  free(sigbytes);
  free(sig.buffer);

  if (!ok) {
    free(man.buffer);
    *err = "release manifest signature INVALID — possible tampering";
    return NULL;
  }
  return man.buffer; /* verified manifest; caller frees */
}

/* One artifact row.  Columns 1-5 are the format ircbot's original updater
 * parses; 6-9 were appended for the network upgrade and are absent from older
 * manifests, which is why they default to a source build that fits anything. */
typedef struct {
  char version[64];
  char url[512];
  char hash[128];
  char deps[256];
  char kind[8];      /* bin | src        */
  char arch[32];     /* x86_64 | any     */
  char libc[16];     /* gnu | musl | any */
  char min_from[64]; /* oldest version this may upgrade FROM; '*' = any */
  char cpu[256];     /* CPU features it needs, "-" = none (column 10)   */
} hub_manifest_row_t;

/* The variant whose tree manifest_select() is reading, for its reasons. */
static const char *g_select_variant = NULL;

/* Is CPU feature `f` present, per /proc/cpuinfo ("flags" on x86_64,
 * "Features" on aarch64; "neon" is that file's "asimd")?  A host whose
 * cpuinfo cannot be read is not refused here: the staged -selftest and the
 * upgrade script's watchdog still stand between it and a build it cannot
 * run.  Mirrors ircbot/utils.c. */
static bool host_cpu_has(const char *f) {
  static char flags[8192];
  static bool loaded = false;
  if (!loaded) {
    loaded = true;
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
      char line[8192];
      while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "flags", 5) != 0 && strncmp(line, "Features", 8) != 0)
          continue;
        const char *colon = strchr(line, ':');
        if (!colon) continue;
        snprintf(flags, sizeof(flags), " %s", colon + 1);
        flags[strcspn(flags, "\r\n")] = '\0';
        size_t fl = strlen(flags);
        if (fl + 1 < sizeof(flags)) {
          flags[fl] = ' ';
          flags[fl + 1] = '\0';
        }
        break;
      }
      fclose(fp);
    }
  }
  if (!flags[0]) return true;
  if (strcmp(f, "neon") == 0) f = "asimd";
  char needle[80];
  snprintf(needle, sizeof(needle), " %s ", f);
  return strstr(flags, needle) != NULL;
}

/* The first CPU feature a row's column 10 names that this host lacks, or
 * NULL.  Entries are comma-separated; "arch:feature" applies only on that
 * arch. */
static const char *row_cpu_missing(const hub_manifest_row_t *r) {
  static char miss[64];
  if (!r->cpu[0] || strcmp(r->cpu, "-") == 0) return NULL;
  char arch[32];
  hub_update_host_arch(arch, sizeof(arch));
  char work[256];
  snprintf(work, sizeof(work), "%s", r->cpu);
  char *save = NULL;
  for (char *e = strtok_r(work, ",", &save); e; e = strtok_r(NULL, ",", &save)) {
    const char *feat = e;
    char *colon = strchr(e, ':');
    if (colon) {
      *colon = '\0';
      if (strcasecmp(e, arch) != 0) continue;
      feat = colon + 1;
    }
    if (!feat[0] || host_cpu_has(feat)) continue;
    snprintf(miss, sizeof(miss), "%s", feat);
    return miss;
  }
  return NULL;
}

static bool row_fits_host(const hub_manifest_row_t *r) {
  char arch[32], libc[16];
  hub_update_host_arch(arch, sizeof(arch));
  hub_update_host_libc(libc, sizeof(libc));
  if (strcmp(r->arch, "any") != 0 && strcasecmp(r->arch, arch) != 0)
    return false;
  if (strcmp(r->libc, "any") != 0 && strcasecmp(r->libc, libc) != 0)
    return false;
  return true;
}

/* Choose the artifact for `version`: a usable prebuilt binary for this host
 * wins, otherwise a source tarball.  `manifest` is consumed (strtok_r), and
 * `reason` explains an empty result.
 *
 * Build dependencies are NOT checked here as the bot's updater does: the hub
 * has no dependency prober, and a source build that cannot compile fails in
 * the upgrade script, which restores the retained binary — see
 * write_upgrade_script. */
static bool manifest_select(char *manifest, const char *version,
                            hub_manifest_row_t *out, char *reason,
                            size_t reason_size) {
  bool have_pick = false;
  snprintf(reason, reason_size, "requested version is not in the manifest");

  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    if (line[0] == '#' || line[0] == '\0') continue;

    hub_manifest_row_t row;
    memset(&row, 0, sizeof(row));
    char date[64];
    snprintf(row.kind, sizeof(row.kind), "src");
    snprintf(row.arch, sizeof(row.arch), "any");
    snprintf(row.libc, sizeof(row.libc), "any");
    snprintf(row.min_from, sizeof(row.min_from), "*");
    snprintf(row.cpu, sizeof(row.cpu), "-");
    int n = sscanf(line, "%63s %63s %511s %127s %255s %7s %31s %15s %63s %255s",
                   row.version, date, row.url, row.hash, row.deps, row.kind,
                   row.arch, row.libc, row.min_from, row.cpu);
    if (n < 5) continue;
    if (!version_eq(row.version, version)) continue;

    if (!validate_url(row.url)) {
      snprintf(reason, reason_size, "untrusted artifact URL in manifest");
      continue;
    }
    if (!row_fits_host(&row)) {
      snprintf(reason, reason_size, "no artifact for this host arch/libc");
      continue;
    }
    const char *lacks = row_cpu_missing(&row);
    if (lacks) {
      snprintf(reason, reason_size, "this CPU lacks %s, which the %s build needs",
               lacks, g_select_variant ? g_select_variant : hub_update_host_variant());
      continue;
    }
    if (strcmp(row.min_from, "*") != 0 &&
        hub_update_version_cmp(HUB_VERSION, row.min_from) < 0) {
      snprintf(reason, reason_size,
               "running version is below the artifact's min_from %s",
               row.min_from);
      continue;
    }
    *out = row;
    have_pick = true;
    if (strcasecmp(row.kind, "bin") == 0) break;
  }
  if (have_pick) reason[0] = '\0';
  return have_pick;
}

/* The checks that need no network: version order, variant, min_from and the
 * unattended-restart password file.  Same version is only "already running"
 * when the variant matches too — a different variant is a switch between
 * the C and Rust builds, which is exactly what an admin's "name=rs" asks. */
static bool can_take_local(const char *target_ver, const char *want_variant,
                           const char *min_from, char *reason,
                           size_t reason_size) {
  if (!target_ver || !target_ver[0]) {
    snprintf(reason, reason_size, "no target version");
    return false;
  }
  int cmp = hub_update_version_cmp(target_ver, HUB_VERSION);
  bool same_variant = strcmp(want_variant, hub_update_host_variant()) == 0;
  if (cmp == 0 && same_variant) {
    snprintf(reason, reason_size, "already running the target version");
    return false;
  }
  if (cmp < 0) {
    snprintf(reason, reason_size, "target is older than the running version");
    return false;
  }
  if (min_from && min_from[0] && strcmp(min_from, "*") != 0 &&
      hub_update_version_cmp(HUB_VERSION, min_from) < 0) {
    snprintf(reason, reason_size,
             "running version is below the target's min_from");
    return false;
  }
  /* An unattended restart needs the machine-bound password file; without it
   * the new binary would stop at a password prompt with nobody to answer. */
  if (access(HUB_PASS_FILE, R_OK) != 0) {
    snprintf(reason, reason_size,
             "no " HUB_PASS_FILE "; cannot restart unattended");
    return false;
  }
  return true;
}

/* <root>/<variant> for a hub release tree, or false when it does not fit or
 * carries anything that could split a URL or a shell word. */
static bool release_tree(const char *base, const char *variant, char *out,
                         size_t out_size) {
  const char *root = effective_root(base);
  if (strlen(root) >= 512 || strpbrk(root, ";|&`$ \t\r\n")) return false;
  if (!variant || !variant[0] || strlen(variant) > 7 ||
      strpbrk(variant, "/;|&`$ \t\r\n"))
    return false;
  return snprintf(out, out_size, "%s/%s", root, variant) < (int)out_size;
}

/* Is `target` a version this hub could move to?  Answered at PREPARE time,
 * and it answers everything COMMIT will need short of the download itself:
 * the signed manifest for the wanted variant must verify and list an
 * artifact that fits this host.  A node that says "ready" here and then
 * cannot fetch its artifact at COMMIT is what turns a routine run into an
 * abort, so the question is asked in full up front.  `min_from` is what the
 * driving hub sent; an empty or "*" value means the manifest decides. */
bool hub_update_can_take(const char *target_ver, const char *variant,
                         const char *min_from, const char *base, char *reason,
                         size_t reason_size) {
  if (reason && reason_size) reason[0] = '\0';
  const char *want_variant =
      (variant && variant[0]) ? variant : hub_update_host_variant();
  if (!can_take_local(target_ver, want_variant, min_from, reason, reason_size))
    return false;

  char tree[600];
  if (!release_tree(base, want_variant, tree, sizeof(tree))) {
    snprintf(reason, reason_size, "rejected malformed manifest base or variant");
    return false;
  }
  /* A run's base travels the way the operator's override does, so artifact
   * URLs under it validate here exactly as they will at COMMIT. */
  if (base && base[0]) setenv("IRCHUB_UPDATE_BASE", base, 1);
  const char *verr = NULL;
  g_fetch_quick = HUB_UPDATE_QUICK_TIMEOUT;
  char *manifest = fetch_verified_manifest(tree, &verr);
  g_fetch_quick = 0;
  if (!manifest) {
    snprintf(reason, reason_size, "%s", verr ? verr : "manifest fetch failed");
    return false;
  }
  hub_manifest_row_t row;
  memset(&row, 0, sizeof(row));
  g_select_variant = want_variant;
  bool picked = manifest_select(manifest, target_ver, &row, reason, reason_size);
  free(manifest);
  if (!picked) {
    /* Can't run this build here — would the other one?  Say so, never
     * switch: which build a node runs is the admin's call. */
    const char *other = strcmp(want_variant, "c") == 0 ? "rs" : "c";
    char otree[600], why_other[320];
    if (strncmp(reason, "this CPU lacks ", 15) == 0 &&
        release_tree(base, other, otree, sizeof(otree))) {
      g_fetch_quick = HUB_UPDATE_QUICK_TIMEOUT;
      char *om = fetch_verified_manifest(otree, &verr);
      g_fetch_quick = 0;
      if (om) {
        hub_manifest_row_t orow;
        memset(&orow, 0, sizeof(orow));
        g_select_variant = other;
        bool fits = manifest_select(om, target_ver, &orow, why_other,
                                    sizeof(why_other));
        free(om);
        if (fits) {
          size_t rl = strlen(reason);
          snprintf(reason + rl, reason_size - rl,
                   " — the %s build fits: select this node with =%s", other,
                   other);
        }
      }
    }
    g_select_variant = NULL;
    return false;
  }
  g_select_variant = NULL;
  if (strncmp(strrchr(row.url, '/') ? strrchr(row.url, '/') + 1 : row.url,
              "irchub-", 7) != 0) {
    snprintf(reason, reason_size, "manifest artifact is not a irchub release");
    return false;
  }
  return true;
}

/* List the distinct versions a release tree offers, newest first — what
 * hub_admin shows so an admin picks a version instead of typing one.  The
 * manifest is signature-verified like any other read of it; an unverifiable
 * one lists nothing. */
int hub_update_list_releases(const char *root, const char *variant,
                             hub_release_t *out, int max, const char **err) {
  *err = NULL;
  char tree[600];
  if (!root || !root[0]) root = effective_root(NULL);
  if (strlen(root) >= 512 ||
      strpbrk(root, ";|&`$ \t\r\n") || !variant || !variant[0] ||
      strlen(variant) > 7 || strpbrk(variant, "/;|&`$ \t\r\n") ||
      snprintf(tree, sizeof(tree), "%s/%s", root, variant) >= (int)sizeof(tree)) {
    *err = "malformed release base";
    return -1;
  }
  g_fetch_quick = HUB_UPDATE_QUICK_TIMEOUT;
  char *manifest = fetch_verified_manifest(tree, err);
  g_fetch_quick = 0;
  if (!manifest) return -1;

  int n = 0;
  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    if (line[0] == '#' || line[0] == '\0') continue;
    char version[64] = "", date[16] = "";
    if (sscanf(line, "%63s %15s", version, date) != 2) continue;
    if (strpbrk(version, "|;&`$")) continue;
    bool dup = false;
    for (int i = 0; i < n && !dup; i++)
      dup = hub_update_version_cmp(out[i].version, version) == 0;
    if (dup) continue;
    if (n >= max) {
      /* Full: keep the newest `max` — replace the oldest if this is newer. */
      int oldest = 0;
      for (int i = 1; i < n; i++)
        if (hub_update_version_cmp(out[i].version, out[oldest].version) < 0)
          oldest = i;
      if (hub_update_version_cmp(version, out[oldest].version) <= 0) continue;
      snprintf(out[oldest].version, sizeof(out[oldest].version), "%s", version);
      snprintf(out[oldest].date, sizeof(out[oldest].date), "%s", date);
      continue;
    }
    snprintf(out[n].version, sizeof(out[n].version), "%s", version);
    snprintf(out[n].date, sizeof(out[n].date), "%s", date);
    n++;
  }
  free(manifest);
  /* Newest first (insertion sort: n is tiny). */
  for (int i = 1; i < n; i++) {
    hub_release_t t = out[i];
    int j = i - 1;
    while (j >= 0 && hub_update_version_cmp(out[j].version, t.version) < 0) {
      out[j + 1] = out[j];
      j--;
    }
    out[j + 1] = t;
  }
  return n;
}

/* ---- Install ----------------------------------------------------------- */

/* Byte-copy with an explicit mode.  Used for the config snapshot, where the
 * original must stay in place (the binary is renamed instead). */
static bool copy_file(const char *src, const char *dst, mode_t mode) {
  int in = open(src, O_RDONLY | O_CLOEXEC);
  if (in < 0) return false;
  int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (out < 0) {
    close(in);
    return false;
  }
  char buf[8192];
  bool ok = true;
  ssize_t n;
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(out, buf + off, (size_t)(n - off));
      if (w <= 0) {
        ok = false;
        break;
      }
      off += w;
    }
    if (!ok) break;
  }
  if (n < 0) ok = false;
  if (ok && fsync(out) != 0) ok = false;
  close(in);
  if (close(out) != 0) ok = false;
  if (!ok) remove(dst);
  return ok;
}

/* Write the upgrade script.  `kind` decides the middle of it: a prebuilt
 * binary is unpacked and moved into place, a source tarball is compiled
 * first.  Either way the previous binary stays at <exe>.prev — the driving
 * hub, not the script, decides whether to keep it. */
/* Run argv[0] with argv, stdout+stderr captured into `out` (first line
 * kept), killed after `timeout_s`.  Returns its exit status, or -1 when it
 * could not run or timed out.  No shell: every argument is passed as-is.
 * Mirrors ircbot/utils.c. */
static int run_bounded(char *const argv[], int timeout_s, char *out,
                       size_t out_size) {
  if (out && out_size) out[0] = '\0';
  int pipefd[2];
  if (pipe(pipefd) != 0) return -1;
  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }
  if (pid == 0) {
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) dup2(devnull, STDIN_FILENO);
    /* Nothing of this process leaks into the child: not the listener, not a
     * peer link, not the PID lock. */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    for (int fd = 3; fd < maxfd; fd++) close(fd);
    execv(argv[0], argv);
    _exit(127);
  }
  close(pipefd[1]);
  fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
  size_t got = 0;
  int status = 0;
  bool done = false;
  for (int waited_ms = 0; waited_ms < timeout_s * 1000; waited_ms += 100) {
    char buf[256];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
      if (out && got + 1 < out_size) {
        size_t take = (size_t)n < out_size - 1 - got ? (size_t)n : out_size - 1 - got;
        memcpy(out + got, buf, take);
        got += take;
        out[got] = '\0';
      }
    }
    if (waitpid(pid, &status, WNOHANG) == pid) {
      done = true;
      break;
    }
    struct timespec tick = {0, 100 * 1000 * 1000};
    nanosleep(&tick, NULL);
  }
  if (!done) {
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
  }
  close(pipefd[0]);
  if (out) out[strcspn(out, "\r\n")] = '\0';
  if (!done) return -1;
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Unpack `archive` into a scratch directory and run the binary in it with
 * -selftest, from this directory (so it reads this config and pass file).
 * Nothing live is touched either way; the scratch directory is removed. */
static bool staged_selftest(const char *archive, char *err, size_t err_size) {
  static const char *dir = "./irchub_selftest_tmp";
  char *rm[] = {"/bin/rm", "-rf", (char *)dir, NULL};
  run_bounded(rm, 30, NULL, 0);
  if (mkdir(dir, 0700) != 0) {
    snprintf(err, err_size, "could not stage the new build for its selftest");
    return false;
  }
  char out[256];
  char *tar[] = {"/bin/tar", "-xzf", (char *)archive, "--strip-components=1",
                 "-C", (char *)dir, NULL};
  if (access("/bin/tar", X_OK) != 0) tar[0] = "/usr/bin/tar";
  if (run_bounded(tar, 60, out, sizeof(out)) != 0) {
    run_bounded(rm, 30, NULL, 0);
    snprintf(err, err_size, "could not unpack the new build for its selftest");
    return false;
  }
  char bin[64];
  snprintf(bin, sizeof(bin), "%s/irchub", dir);
  char *st[] = {bin, "-selftest", NULL};
  int rc = run_bounded(st, UPGRADE_SELFTEST_SECS, out, sizeof(out));
  run_bounded(rm, 30, NULL, 0);
  if (rc != 0) {
    if (out[0])
      snprintf(err, err_size, "new build failed its selftest: %.160s", out);
    else if (rc < 0)
      snprintf(err, err_size, "new build failed its selftest: timed out after %d s",
               UPGRADE_SELFTEST_SECS);
    else
      snprintf(err, err_size, "new build failed its selftest: exited with %d", rc);
    return false;
  }
  return true;
}

static bool write_upgrade_script(const hub_state_t *state, const char *kind,
                                 const char *archive, const char *prev_path,
                                 bool selftest) {
  /* 0700 at creation: no umask-dependent window on a script we are about to
   * exec. */
  int fd = open(HUB_UPGRADE_SCRIPT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                0700);
  FILE *f = (fd >= 0) ? fdopen(fd, "w") : NULL;
  if (!f) {
    if (fd >= 0) close(fd);
    return false;
  }
  const char *exe = state->executable_path;
  bool is_bin = (strcasecmp(kind, "bin") == 0);

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "set -u\n");
  fprintf(f, "OLD_PID=%d\n", getpid());
  /* The hub execs this script, so OLD_PID is usually the script itself;
   * waiting on it would only burn 30 s of every restart. */
  fprintf(f, "for i in $(seq 1 30); do\n");
  fprintf(f, "  [ \"$OLD_PID\" = \"$$\" ] && break\n");
  fprintf(f, "  kill -0 $OLD_PID 2>/dev/null || break\n");
  fprintf(f, "  sleep 1\n");
  fprintf(f, "done\n");
  fprintf(f, "UPGRADE_DIR=\"./hub_build_tmp\"\n");
  fprintf(f, "rm -rf \"$UPGRADE_DIR\"\n");
  fprintf(f, "mkdir \"$UPGRADE_DIR\" || exit 1\n");
  /* One rollback path for every failure below: put <exe>.prev back and run
   * it, so a hub that cannot upgrade still comes back on the old build. */
  fprintf(f, "rollback() {\n");
  fprintf(f, "  echo \"[UPGRADE] FAILED: $1 — restoring previous build\"\n");
  fprintf(f, "  mv -f \"%s\" \"%s\" 2>/dev/null\n", prev_path, exe);
  /* The marker stays: the old build reports "version-mismatch" on its first
   * peer link, so the driver learns of the failure at once. */
  fprintf(f, "  rm -f \"%s\"\n", HUB_PID_FILE);
  fprintf(f, "  rm -rf \"$UPGRADE_DIR\" \"%s\"\n", archive);
  fprintf(f, "  exec \"%s\"\n", exe);
  fprintf(f, "}\n");
  fprintf(f,
          "tar -xzf \"%s\" --strip-components=1 -C \"$UPGRADE_DIR\" "
          "2>/dev/null || rollback \"could not extract artifact\"\n",
          archive);

  if (is_bin) {
    /* Prebuilt: the tarball holds the binary itself, no toolchain needed.
     * No "run it once" probe — irchub has no --version flag and starting a
     * second instance would fight the one we are replacing for the pid lock.
     * The driving hub is the health monitor: it waits for this node to
     * reappear on the target version and aborts if it never does. */
    fprintf(f, "NEW_BIN=\"$UPGRADE_DIR/irchub\"\n");
    fprintf(f, "chmod 700 \"$NEW_BIN\" 2>/dev/null\n");
    fprintf(f, "[ -x \"$NEW_BIN\" ] || rollback \"artifact binary is not executable\"\n");
  } else {
    fprintf(f, "cd \"$UPGRADE_DIR\" || rollback \"build directory vanished\"\n");
    fprintf(f, "if [ -f Cargo.toml ]; then\n");
    fprintf(f, "  cargo build --release >build.log 2>&1\n");
    fprintf(f, "  BUILT=target/release/irchub\n");
    fprintf(f, "else\n");
    fprintf(f, "  make clean >/dev/null 2>&1\n");
    fprintf(f, "  make >make.log 2>&1\n");
    fprintf(f, "  BUILT=bin/irchub\n");
    fprintf(f, "  [ -f \"$BUILT\" ] || BUILT=irchub\n");
    fprintf(f, "fi\n");
    fprintf(f, "cd ..\n");
    fprintf(f, "NEW_BIN=\"$UPGRADE_DIR/$BUILT\"\n");
    fprintf(f, "[ -f \"$NEW_BIN\" ] || rollback \"build failed (see $UPGRADE_DIR)\"\n");
    /* A prebuilt binary was selftested before the swap; a source build can
     * only be checked here, once it exists. */
    if (selftest)
      fprintf(f, "\"$NEW_BIN\" -selftest >/dev/null 2>&1 || rollback \"new build failed its selftest\"\n");
  }

  /* Atomic same-directory rename into place; <exe> was already renamed to
   * <exe>.prev, which we keep for the run's rollback window. */
  fprintf(f, "mv -f \"$NEW_BIN\" \"%s\" || rollback \"could not install new binary\"\n", exe);
  fprintf(f, "chmod 700 \"%s\"\n", exe);
  fprintf(f, "rm -f \"%s\"\n", HUB_PID_FILE);
  fprintf(f, "rm -rf \"$UPGRADE_DIR\" \"%s\" 2>/dev/null\n", archive);
  /* Startup watchdog.  The new build daemonizes, so the script outlives it:
   * start it, give it UPGRADE_WATCH_SECS, and if its daemon is not alive by
   * then put the retained build (and config) back and start that instead.  A
   * build that cannot even come up — a CPU it cannot run on, a config it
   * cannot read — then costs one restart, not a dead node that only an admin
   * can revive.  The marker is kept, so the old build reports
   * "version-mismatch" on its first peer link and the driver aborts at once
   * rather than waiting out UPGRADE_COMMIT_TIMEOUT. */
  fprintf(f, "\"%s\" </dev/null >/dev/null 2>&1\n", exe);
  fprintf(f, "sleep %d\n", UPGRADE_WATCH_SECS);
  fprintf(f, "P=$(cat \"%s\" 2>/dev/null | tr -dc 0-9)\n", HUB_PID_FILE);
  fprintf(f, "if [ -z \"$P\" ] || ! kill -0 \"$P\" 2>/dev/null; then\n");
  fprintf(f, "  echo \"[UPGRADE] new build did not stay up — restoring previous build\"\n");
  fprintf(f, "  mv -f \"%s\" \"%s.failed\" 2>/dev/null\n", exe, exe);
  fprintf(f, "  mv -f \"%s\" \"%s\" || exit 1\n", prev_path, exe);
  fprintf(f, "  [ -f \"%s%s\" ] && cp -f \"%s%s\" \"%s\"\n", HUB_CONFIG_FILE,
          HUB_UPGRADE_PREV_SUFFIX, HUB_CONFIG_FILE, HUB_UPGRADE_PREV_SUFFIX,
          HUB_CONFIG_FILE);
  fprintf(f, "  rm -f \"%s\" \"./%s\"\n", HUB_PID_FILE, HUB_UPGRADE_SCRIPT);
  fprintf(f, "  exec \"%s\"\n", exe);
  fprintf(f, "fi\n");
  fprintf(f, "rm -f \"./%s\"\n", HUB_UPGRADE_SCRIPT);
  fprintf(f, "exit 0\n");

  (void)fchmod(fileno(f), 0700);
  return fclose(f) == 0;
}

/* Run the upgrade this hub was committed to.  Returns false with *err set
 * when nothing was touched (the caller answers CMD_UPGRADE_RESULT fail and
 * stays on the current build); on success it does not return — the process is
 * replaced and reports in after the restart. */
bool hub_update_commit(hub_state_t *state, const char *upgrade_id,
                       const char *target_ver, const char *variant,
                       const char *base, const char **err) {
  *err = NULL;
  if (!state || !upgrade_id || !target_ver) {
    *err = "malformed upgrade command";
    return false;
  }
  if (!state->executable_path[0]) {
    *err = "this hub does not know its own executable path";
    return false;
  }

  const char *want_variant =
      (variant && variant[0]) ? variant : hub_update_host_variant();
  if (strpbrk(want_variant, "/;|&`$ \t\r\n") || strlen(want_variant) > 7) {
    *err = "rejected malformed variant";
    return false;
  }
  static char why[320];
  if (!can_take_local(target_ver, want_variant, NULL, why, sizeof(why))) {
    *err = why[0] ? why : "cannot take this version";
    return false;
  }
  /* The driving hub names the release tree ROOT; the variant picks the
   * subtree.  That is what lets one run leave each node on its own kind of
   * build — and lets an admin move a hub from the C build to the Rust one. */
  const char *root = effective_root(base);
  if (strlen(root) >= 512 || strpbrk(root, ";|&`$ \t\r\n")) {
    *err = "rejected malformed manifest base";
    return false;
  }
  char tree[600];
  if (snprintf(tree, sizeof(tree), "%s/%s", root, want_variant) >=
      (int)sizeof(tree)) {
    *err = "manifest base too long";
    return false;
  }
  /* Hand the base on the way the operator's override travels, so validate_url
   * accepts artifact URLs under it and a local tree needs nothing else. */
  if (base && base[0]) setenv("IRCHUB_UPDATE_BASE", base, 1);

  hub_log_info("[UPGRADE] Commit %s: %s -> %s (variant %s)\n", upgrade_id,
          HUB_VERSION, target_ver, want_variant);

  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(tree, &verr);
  if (!manifest) {
    *err = verr ? verr : "manifest fetch failed";
    return false;
  }

  hub_manifest_row_t row;
  memset(&row, 0, sizeof(row));
  static char pick_why[320];
  g_select_variant = want_variant;
  bool picked = manifest_select(manifest, target_ver, &row, pick_why,
                                sizeof(pick_why));
  g_select_variant = NULL;
  free(manifest);
  if (!picked) {
    *err = pick_why[0] ? pick_why : "no usable artifact";
    return false;
  }

  char archive[256];
  const char *slash = strrchr(row.url, '/');
  if (!sanitize_filename(slash ? slash + 1 : "irchub.tar.gz", archive,
                         sizeof(archive))) {
    *err = "artifact filename in manifest is not acceptable";
    return false;
  }

  /* Every release artifact is named "<product>-…tar.gz" (see the releases
   * repo README).  A base override that names the OTHER product's tree would
   * otherwise hand this daemon the wrong binary and install it over itself —
   * fail closed here instead, where nothing has been downloaded yet. */
  if (strncmp(archive, "irchub-", 7) != 0) {
    *err = "manifest artifact is not a irchub release";
    return false;
  }

  hub_log_info("[UPGRADE] Fetching %s artifact %s\n", row.kind, archive);
  if (!download_file(row.url, archive)) {
    *err = "artifact download failed";
    return false;
  }
  if (!verify_sha256(archive, row.hash)) {
    remove(archive);
    *err = "artifact SHA-256 mismatch";
    return false;
  }

  /* Run the NEW binary's -selftest before anything is swapped: CPU, libraries
   * and this very config, checked by the build that would have to run on
   * them.  A target older than -selftest would take the flag for a normal
   * start, so it is never run; a source build is checked by the script. */
  bool can_selftest =
      hub_update_version_cmp(target_ver, UPGRADE_SELFTEST_MIN_HUB) >= 0;
  if (can_selftest && strcasecmp(row.kind, "bin") == 0) {
    static char st_err[320];
    if (!staged_selftest(archive, st_err, sizeof(st_err))) {
      remove(archive);
      *err = st_err;
      return false;
    }
    hub_log_info("[UPGRADE] Staged %s passed its selftest\n", target_ver);
  }

  /* Flush the live config, then snapshot the pair we may have to restore.
   * The config is copied (this hub still needs it); the binary is renamed,
   * which is atomic and leaves <exe>.prev ready for a rollback. */
  hub_config_write(state);
  char prev_cfg[PATH_MAX];
  char prev_exe[PATH_MAX + 8];
  if (snprintf(prev_cfg, sizeof(prev_cfg), "%s%s", HUB_CONFIG_FILE,
               HUB_UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_cfg) ||
      snprintf(prev_exe, sizeof(prev_exe), "%s%s", state->executable_path,
               HUB_UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_exe)) {
    remove(archive);
    *err = "path too long for rollback snapshot";
    return false;
  }
  if (!copy_file(HUB_CONFIG_FILE, prev_cfg, 0600)) {
    remove(archive);
    *err = "could not snapshot config for rollback";
    return false;
  }
  if (rename(state->executable_path, prev_exe) != 0) {
    remove(prev_cfg);
    remove(archive);
    *err = "could not retain previous binary";
    return false;
  }
  /* From here a failure is the script's to handle: it restores <exe>.prev and
   * restarts the old build rather than leaving this hub with no binary. */
  if (!hub_upgrade_marker_write(upgrade_id, target_ver, want_variant) ||
      !write_upgrade_script(state, row.kind, archive, prev_exe, can_selftest)) {
    remove(HUB_UPGRADE_MARKER_FILE);
    rename(prev_exe, state->executable_path);
    remove(prev_cfg);
    remove(archive);
    *err = "could not stage the upgrade script";
    return false;
  }

  hub_log_info("[UPGRADE] Installing %s and restarting\n", target_ver);
  if (state->pid_fd >= 0) close(state->pid_fd);
  sleep(1);
  hub_update_close_fds_for_exec();
  execl("./" HUB_UPGRADE_SCRIPT, "./" HUB_UPGRADE_SCRIPT, (char *)NULL);
  /* exec failed: put the old binary back so this hub is not left dead.  The
   * sockets are already gone, so exiting is all that is left. */
  rename(prev_exe, state->executable_path);
  remove(HUB_UPGRADE_MARKER_FILE);
  exit(1);
}

/* ---- Multi-version stepping (upgrade plan, Task 7) ---------------------
 * A manifest row may declare a min_from_version: the oldest release it is
 * willing to be installed over.  A node further back than that cannot jump
 * straight to the target, so the run walks it there one release at a time.
 * This reads the manifest for ANOTHER node — a bot on its own release tree,
 * or a peer hub — so the host arch/libc filter is deliberately not applied:
 * the node itself picks the artifact when it commits.  Returns the highest
 * version `cur_ver` may take right now on the way to `target_ver`. */
bool hub_update_next_step(const char *base, const char *variant,
                          const char *cur_ver, const char *target_ver,
                          char *out, size_t out_size, char *reason,
                          size_t reason_size) {
  if (out && out_size) out[0] = '\0';
  if (reason && reason_size) reason[0] = '\0';
  if (!cur_ver || !target_ver || !target_ver[0]) {
    snprintf(reason, reason_size, "no target version");
    return false;
  }

  char tree[600];
  const char *root = (base && base[0]) ? base : HUB_UPDATE_BASE;
  const char *var = (variant && variant[0]) ? variant : hub_update_host_variant();
  if (snprintf(tree, sizeof(tree), "%s/%s", root, var) >= (int)sizeof(tree)) {
    snprintf(reason, reason_size, "release base URL too long");
    return false;
  }

  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(tree, &verr);
  if (!manifest) {
    snprintf(reason, reason_size, "%s", verr ? verr : "manifest fetch failed");
    return false;
  }

  char best[64] = "";
  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    if (line[0] == '#' || line[0] == '\0') continue;
    char version[64] = "", date[64], url[512], hash[128], deps[256];
    char kind[8] = "src", arch[32] = "any", libc[16] = "any";
    char min_from[64] = "*";
    int n = sscanf(line, "%63s %63s %511s %127s %255s %7s %31s %15s %63s",
                   version, date, url, hash, deps, kind, arch, libc, min_from);
    if (n < 5 || !version[0]) continue;
    /* Strictly forward, and never past where the run is going. */
    if (hub_update_version_cmp(version, cur_ver) <= 0) continue;
    if (hub_update_version_cmp(version, target_ver) > 0) continue;
    /* Reachable from where the node is now. */
    if (strcmp(min_from, "*") != 0 &&
        hub_update_version_cmp(cur_ver, min_from) < 0)
      continue;
    if (!best[0] || hub_update_version_cmp(version, best) > 0)
      snprintf(best, sizeof(best), "%s", version);
  }
  free(manifest);

  if (!best[0]) {
    snprintf(reason, reason_size,
             "no release in the manifest can be installed over %s", cur_ver);
    return false;
  }
  snprintf(out, out_size, "%s", best);
  return true;
}

/* irchub -checkupdate [variant]: fetch the irchub release manifest and its
 * signature exactly as a hub self-upgrade does — <root>/<variant>, the
 * compiled-in root and pinned key unless IRCHUB_UPDATE_BASE says otherwise —
 * verify one against the other, and report.  Nothing past the manifest is
 * downloaded and nothing is installed, so an operator (or the testnet) can
 * prove a host reaches and trusts the real release channel — TLS, CA store,
 * pinned key — without upgrading anything.  0 = verified. */
int hub_update_check_cli(const char *variant) {
  const char *want = (variant && variant[0]) ? variant : hub_update_host_variant();
  if (strpbrk(want, "/;|&`$ \t\r\n") || strlen(want) > 7) {
    printf("checkupdate: FAIL malformed variant\n");
    return 1;
  }
  char tree[600];
  if (snprintf(tree, sizeof(tree), "%s/%s", effective_root(NULL), want) >=
      (int)sizeof(tree)) {
    printf("checkupdate: FAIL release base URL too long\n");
    return 1;
  }
  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(tree, &verr);
  if (!manifest) {
    printf("checkupdate: FAIL %s (%s)\n", verr ? verr : "manifest fetch failed",
           tree);
    return 1;
  }
  int rows = 0;
  char newest[64] = "";
  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char version[64];
    if (line[0] == '#' || sscanf(line, "%63s", version) != 1) continue;
    rows++;
    if (!newest[0] || hub_update_version_cmp(version, newest) > 0)
      snprintf(newest, sizeof(newest), "%s", version);
  }
  free(manifest);
  printf("checkupdate: OK %s manifest verified: %d release row(s), newest %s, "
         "running %s\n",
         want, rows, newest[0] ? newest : "-", HUB_VERSION);
  return 0;
}

#else /* !HAVE_CURL */

int hub_update_check_cli(const char *variant) {
  (void)variant;
  printf("checkupdate: FAIL hub built without curl support\n");
  return 1;
}

bool hub_update_next_step(const char *base, const char *variant,
                          const char *cur_ver, const char *target_ver,
                          char *out, size_t out_size, char *reason,
                          size_t reason_size) {
  (void)base;
  (void)variant;
  (void)cur_ver;
  (void)target_ver;
  if (out && out_size) out[0] = '\0';
  if (reason && reason_size)
    snprintf(reason, reason_size, "hub built without curl support");
  return false;
}

int hub_update_list_releases(const char *root, const char *variant,
                             hub_release_t *out, int max, const char **err) {
  (void)root;
  (void)variant;
  (void)out;
  (void)max;
  *err = "hub built without curl support";
  return -1;
}

bool hub_update_can_take(const char *target_ver, const char *variant,
                         const char *min_from, const char *base, char *reason,
                         size_t reason_size) {
  (void)target_ver;
  (void)variant;
  (void)min_from;
  (void)base;
  if (reason && reason_size)
    snprintf(reason, reason_size, "hub built without curl support");
  return false;
}

bool hub_update_commit(hub_state_t *state, const char *upgrade_id,
                       const char *target_ver, const char *variant,
                       const char *base, const char **err) {
  (void)state;
  (void)upgrade_id;
  (void)target_ver;
  (void)variant;
  (void)base;
  *err = "hub built without curl support";
  return false;
}

#endif /* HAVE_CURL */
