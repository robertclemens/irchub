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
bool hub_upgrade_marker_write(const char *upgrade_id, const char *target_ver) {
  if (!upgrade_id || !target_ver) return false;
  int fd = open(HUB_UPGRADE_MARKER_FILE,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  char line[256];
  int n = snprintf(line, sizeof(line), "%s|%s\n", upgrade_id, target_ver);
  bool ok = (n > 0 && n < (int)sizeof(line) && write(fd, line, (size_t)n) == n);
  if (close(fd) != 0) ok = false;
  if (!ok) remove(HUB_UPGRADE_MARKER_FILE);
  return ok;
}

/* Read and consume the marker.  False for every ordinary start. */
bool hub_update_take_pending(char *id_out, size_t id_size, char *ver_out,
                             size_t ver_size) {
  if (!id_out || !ver_out || id_size == 0 || ver_size == 0) return false;
  id_out[0] = ver_out[0] = '\0';

  FILE *f = fopen(HUB_UPGRADE_MARKER_FILE, "r");
  if (!f) return false;
  char line[256] = "";
  bool got = (fgets(line, sizeof(line), f) != NULL);
  fclose(f);
  /* Consumed whatever it said: a marker we cannot parse must not be retried
   * on every reconnect for the rest of this process's life. */
  remove(HUB_UPGRADE_MARKER_FILE);
  if (!got) return false;

  char id[64] = "", ver[64] = "";
  if (sscanf(line, "%63[^|\r\n]|%63[^\r\n]", id, ver) != 2) return false;
  if (!id[0] || !ver[0]) return false;
  snprintf(id_out, id_size, "%s", id);
  snprintf(ver_out, ver_size, "%s", ver);
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

static void curl_common(CURL *h, const char *url) {
  curl_easy_setopt(h, CURLOPT_URL, url);
  curl_easy_setopt(h, CURLOPT_USERAGENT, "irchub-updater/1.0");
  curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 30L);
  curl_easy_setopt(h, CURLOPT_TIMEOUT, HUB_UPDATE_FETCH_TIMEOUT);
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
} hub_manifest_row_t;

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
    int n = sscanf(line, "%63s %63s %511s %127s %255s %7s %31s %15s %63s",
                   row.version, date, row.url, row.hash, row.deps, row.kind,
                   row.arch, row.libc, row.min_from);
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

/* Is `target` a version this hub could move to at all?  Answered at PREPARE
 * time, before anything is downloaded, so the run's roster is honest about a
 * hub that has no usable artifact.  `min_from` is what the driving hub sent;
 * an empty or "*" value means the manifest decides. */
bool hub_update_can_take(const char *target_ver, const char *min_from,
                         const char *base, char *reason, size_t reason_size) {
  if (reason && reason_size) reason[0] = '\0';
  if (!target_ver || !target_ver[0]) {
    snprintf(reason, reason_size, "no target version");
    return false;
  }
  int cmp = hub_update_version_cmp(target_ver, HUB_VERSION);
  if (cmp == 0) {
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
  (void)base; /* the artifact itself is chosen at COMMIT */
  return true;
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
static bool write_upgrade_script(const hub_state_t *state, const char *kind,
                                 const char *archive, const char *prev_path) {
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
  fprintf(f, "for i in $(seq 1 30); do\n");
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
  fprintf(f, "  rm -f \"%s\" \"%s\"\n", HUB_PID_FILE, HUB_UPGRADE_MARKER_FILE);
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
  }

  /* Atomic same-directory rename into place; <exe> was already renamed to
   * <exe>.prev, which we keep for the run's rollback window. */
  fprintf(f, "mv -f \"$NEW_BIN\" \"%s\" || rollback \"could not install new binary\"\n", exe);
  fprintf(f, "chmod 700 \"%s\"\n", exe);
  fprintf(f, "rm -f \"%s\"\n", HUB_PID_FILE);
  fprintf(f, "(sleep 5; rm -rf \"$UPGRADE_DIR\" \"%s\" \"./%s\" 2>/dev/null) &\n",
          archive, HUB_UPGRADE_SCRIPT);
  fprintf(f, "exec \"%s\"\n", exe);

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

  char why[320];
  if (!hub_update_can_take(target_ver, NULL, base, why, sizeof(why))) {
    *err = why[0] ? why : "cannot take this version";
    return false;
  }

  const char *want_variant =
      (variant && variant[0]) ? variant : hub_update_host_variant();
  if (strpbrk(want_variant, "/;|&`$ \t\r\n") || strlen(want_variant) > 7) {
    *err = "rejected malformed variant";
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
  bool picked = manifest_select(manifest, target_ver, &row, pick_why,
                                sizeof(pick_why));
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
  if (!hub_upgrade_marker_write(upgrade_id, target_ver) ||
      !write_upgrade_script(state, row.kind, archive, prev_exe)) {
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

bool hub_update_can_take(const char *target_ver, const char *min_from,
                         const char *base, char *reason, size_t reason_size) {
  (void)target_ver;
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
