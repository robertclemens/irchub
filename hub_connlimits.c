/* Per-hub connection limits: `hub set ssh ...` and `hub set conn ...`
 * (docs/modes.md §9.3, D26, D35; docs/console.md).
 *
 * Three independent pieces, all free of the console thread and of
 * hub_state_t internals beyond the plain tables handed in:
 *   - the setting table (names, ranges, built-ins, parsing, canonical text),
 *   - the SSH-only address table (connect window, refused logins, escalating
 *     block), separate from the shared ip_limits table,
 *   - the eviction choice used when every SSH login slot is taken.
 * Main thread only, except hub_ssh_evict_pick which the console thread calls
 * on its own copies. */
#include "hub.h"
#include <stddef.h>

typedef enum { K_INT, K_RATE, K_RATE3 } ck_t;

typedef struct {
  int         group;       /* HUB_CONN_SSH / HUB_CONN_CONN */
  const char *name;
  ck_t        kind;
  size_t      off[3];      /* int members of hub_conn_cfg_t */
  int         def[3];
  int         lo[3], hi[3];
  const char *range;       /* shown in errors */
} cset_t;

#define O(m) offsetof(hub_conn_cfg_t, m)

static const cset_t SETS[] = {
  {HUB_CONN_SSH, "preauth", K_INT, {O(preauth)}, {CONSOLE_MAX_PREAUTH}, {1}, {CONSOLE_MAX_PREAUTH_CAP},
   "1 to 64"},
  {HUB_CONN_SSH, "preauthip", K_INT, {O(preauthip)}, {SSH_DEF_PREAUTHIP}, {1}, {CONSOLE_MAX_PREAUTH_CAP},
   "1 to the preauth value"},
  {HUB_CONN_SSH, "sessions", K_INT, {O(sessions)}, {CONSOLE_MAX_SESSIONS}, {1}, {32}, "1 to 32"},
  {HUB_CONN_SSH, "grace", K_INT, {O(grace)}, {CONSOLE_LOGIN_GRACE}, {5}, {120}, "5 to 120 seconds"},
  {HUB_CONN_SSH, "authtries", K_INT, {O(authtries)}, {CONSOLE_MAX_AUTH_TRIES}, {1}, {6}, "1 to 6"},
  {HUB_CONN_SSH, "idle", K_INT, {O(idle)}, {CONSOLE_IDLE_TIMEOUT}, {60}, {86400},
   "60 to 86400 seconds"},
  {HUB_CONN_SSH, "authfail", K_RATE, {O(authfail_n), O(authfail_s)},
   {SSH_DEF_AUTHFAIL_N, SSH_DEF_AUTHFAIL_S}, {1, 1}, {1000, 86400}, "N:S, N 1 to 1000, S 1 to 86400"},
  {HUB_CONN_SSH, "connect", K_RATE, {O(connect_n), O(connect_s)},
   {SSH_DEF_CONNECT_N, SSH_DEF_CONNECT_S}, {2, 1}, {1000, 3600}, "N:S, N 2 to 1000, S 1 to 3600"},
  {HUB_CONN_SSH, "block", K_INT, {O(block)}, {SSH_DEF_BLOCK}, {30}, {SSH_BLOCK_MAX},
   "30 to 86400 seconds"},
  {HUB_CONN_SSH, "cmdrate", K_RATE, {O(cmdrate_n), O(cmdrate_s)},
   {SSH_DEF_CMDRATE_N, SSH_DEF_CMDRATE_S}, {1, 1}, {1000, 3600}, "N:S, N 1 to 1000, S 1 to 3600"},
  {HUB_CONN_CONN, "perip", K_INT, {O(perip)}, {MAX_CONNECTIONS_PER_IP}, {2}, {64}, "2 to 64"},
  {HUB_CONN_CONN, "churn", K_RATE3, {O(churn_n), O(churn_s), O(churn_block)},
   {CHURN_MAX_CONNS, CHURN_WINDOW_SEC, CHURN_BLOCK_SEC}, {2, 1, 30}, {1000, 3600, SSH_BLOCK_MAX},
   "N:S[:B], N 2 to 1000, S 1 to 3600, B 30 to 86400"},
  {HUB_CONN_CONN, "authfail", K_RATE3, {O(fail_n), O(fail_s), O(fail_block)},
   {MAX_FAILED_AUTH_ATTEMPTS, FAILED_AUTH_RESET_TIME, FAILED_AUTH_BLOCK_DURATION}, {1, 1, 30},
   {1000, 86400, SSH_BLOCK_MAX}, "N:S[:B], N 1 to 1000, S 1 to 86400, B 30 to 86400"},
  {HUB_CONN_CONN, "startups", K_RATE3, {O(startups_start), O(startups_rate), O(startups_full)},
   {STARTUPS_DEF_START, STARTUPS_DEF_RATE, STARTUPS_DEF_FULL}, {1, 1, 1},
   {MAX_CLIENTS, 100, MAX_CLIENTS}, "S:R[:F], S 1 to 100, R 1 to 100 (%), F 1 to 100"},
};
#undef O
#define NSETS ((int)(sizeof(SETS) / sizeof(SETS[0])))

/* off[] holds offsetof() of int fields; memcpy reaches them without an
 * aligning pointer cast. */
static void mem_set(hub_conn_cfg_t *c, const cset_t *s, int i, int v) {
  memcpy((char *)c + s->off[i], &v, sizeof(v));
}
static int memv(const hub_conn_cfg_t *c, const cset_t *s, int i) {
  int v;
  memcpy(&v, (const char *)c + s->off[i], sizeof(v));
  return v;
}
static int nparts(const cset_t *s) { return s->kind == K_INT ? 1 : s->kind == K_RATE ? 2 : 3; }

static const cset_t *find_set(int group, const char *name) {
  if (!name) return NULL;
  for (int i = 0; i < NSETS; i++)
    if (SETS[i].group == group && strcmp(SETS[i].name, name) == 0) return &SETS[i];
  return NULL;
}

void hub_conn_cfg_defaults(hub_conn_cfg_t *c) {
  memset(c, 0, sizeof(*c));
  for (int i = 0; i < NSETS; i++)
    for (int k = 0; k < nparts(&SETS[i]); k++) mem_set(c, &SETS[i], k, SETS[i].def[k]);
}

int hub_conn_cfg_count(int group) {
  int n = 0;
  for (int i = 0; i < NSETS; i++)
    if (SETS[i].group == group) n++;
  return n;
}

const char *hub_conn_cfg_name(int group, int idx) {
  for (int i = 0; i < NSETS; i++)
    if (SETS[i].group == group && idx-- == 0) return SETS[i].name;
  return NULL;
}

static void fmt_value(const cset_t *s, const int v[3], char *out, size_t cap) {
  if (s->kind == K_INT) snprintf(out, cap, "%d", v[0]);
  else if (s->kind == K_RATE) snprintf(out, cap, "%d:%d", v[0], v[1]);
  else snprintf(out, cap, "%d:%d:%d", v[0], v[1], v[2]);
}

bool hub_conn_cfg_get(const hub_conn_cfg_t *c, int group, const char *name, char *out,
                      size_t cap) {
  const cset_t *s = find_set(group, name);
  if (!s) return false;
  int v[3] = {0, 0, 0};
  for (int k = 0; k < nparts(s); k++) v[k] = memv(c, s, k);
  fmt_value(s, v, out, cap);
  return true;
}

bool hub_conn_cfg_default(int group, const char *name, char *out, size_t cap) {
  const cset_t *s = find_set(group, name);
  if (!s) return false;
  fmt_value(s, s->def, out, cap);
  return true;
}

bool hub_conn_cfg_is_default(const hub_conn_cfg_t *c, int group, const char *name) {
  const cset_t *s = find_set(group, name);
  if (!s) return true;
  for (int k = 0; k < nparts(s); k++)
    if (memv(c, s, k) != s->def[k]) return false;
  return true;
}

/* The per-address login limit actually enforced: never above the total. */
int hub_conn_cfg_preauthip(const hub_conn_cfg_t *c) {
  return c->preauthip < c->preauth ? c->preauthip : c->preauth;
}

/* Strict "N", "N:S" or "N:S:B": decimal digits only, each part inside its
 * range.  A two-part value for a three-part setting keeps the current
 * third part (cur). */
static bool parse_value(const cset_t *s, const char *in, const int cur[3], int out[3]) {
  if (!in || !*in || strlen(in) > 40) return false;
  char buf[48];
  snprintf(buf, sizeof(buf), "%s", in);
  int n = 0;
  char *save = NULL;
  for (char *p = strtok_r(buf, ":", &save); p; p = strtok_r(NULL, ":", &save)) {
    if (n >= 3) return false;
    unsigned long v;
    if (!hub_parse_uint(p, 1000000ul, &v)) return false;
    out[n++] = (int)v;
  }
  /* strtok_r folds "3::5" and a trailing ':' away: count separators too */
  int colons = 0;
  for (const char *p = in; *p; p++)
    if (*p == ':') colons++;
  if (colons != n - 1) return false;
  int need = nparts(s);
  if (n == need - 1 && s->kind == K_RATE3) out[n++] = cur[2];
  if (n != need) return false;
  for (int k = 0; k < need; k++)
    if (out[k] < s->lo[k] || out[k] > s->hi[k]) return false;
  return true;
}

hub_conn_set_t hub_conn_cfg_set(hub_conn_cfg_t *c, int group, const char *name,
                                const char *value, char *why, size_t whycap) {
  const cset_t *s = find_set(group, name);
  if (!s) return HUB_CONN_UNKNOWN;
  int cur[3] = {0, 0, 0}, nv[3] = {0, 0, 0};
  for (int k = 0; k < nparts(s); k++) cur[k] = memv(c, s, k);
  if (!value || strcmp(value, "default") == 0) {
    for (int k = 0; k < 3; k++) nv[k] = s->def[k];
  } else {
    if (!parse_value(s, value, cur, nv)) {
      snprintf(why, whycap, "%s %s takes %s", group == HUB_CONN_SSH ? "ssh" : "conn", s->name,
               s->range);
      return HUB_CONN_BAD;
    }
    /* preauthip cannot exceed preauth */
    if (group == HUB_CONN_SSH && strcmp(s->name, "preauthip") == 0 && nv[0] > c->preauth) {
      snprintf(why, whycap, "ssh preauthip takes 1 to %d (the preauth value)", c->preauth);
      return HUB_CONN_BAD;
    }
  }
  for (int k = 0; k < nparts(s); k++) mem_set(c, s, k, nv[k]);
  return HUB_CONN_OK;
}

/* A config line body "<name>|<value>"; false (and nothing changed) if the
 * name or value is not valid, so a damaged file never loosens a limit. */
bool hub_conn_cfg_load(hub_conn_cfg_t *c, int group, const char *body) {
  char buf[96];
  if (!body || strlen(body) >= sizeof(buf)) return false;
  snprintf(buf, sizeof(buf), "%s", body);
  char *sep = strchr(buf, '|');
  if (!sep) return false;
  *sep = '\0';
  char why[96];
  if (strcmp(sep + 1, "default") == 0) return false;
  return hub_conn_cfg_set(c, group, buf, sep + 1, why, sizeof(why)) == HUB_CONN_OK;
}

/* Config lines for everything that differs from the built-ins. */
size_t hub_conn_cfg_lines(const hub_conn_cfg_t *c, char *out, size_t cap) {
  size_t o = 0;
  for (int g = 0; g < 2; g++) {
    for (int i = 0; i < NSETS; i++) {
      if (SETS[i].group != g || hub_conn_cfg_is_default(c, g, SETS[i].name)) continue;
      char v[48];
      hub_conn_cfg_get(c, g, SETS[i].name, v, sizeof(v));
      int w = snprintf(out + o, cap - o, "%s|%s|%s\n", g == HUB_CONN_SSH ? "ssh" : "conn",
                       SETS[i].name, v);
      if (w < 0 || (size_t)w >= cap - o) return (size_t)-1;
      o += (size_t)w;
    }
  }
  return o;
}

/* After a load, make the combination coherent (a hand-edited file). */
void hub_conn_cfg_fix(hub_conn_cfg_t *c) {
  if (c->preauthip > c->preauth) c->preauthip = c->preauth;
}

/* ==========================================================================
 * The SSH address table (D26)
 * ========================================================================== */
static ssh_ip_t *ssh_find(ssh_ip_t *tab, int *count, const char *ip, time_t now) {
  for (int i = 0; i < *count; i++)
    if (strcmp(tab[i].ip, ip) == 0) {
      tab[i].last_seen = now;
      return &tab[i];
    }
  int slot;
  if (*count < MAX_SSH_IPS) {
    slot = (*count)++;
  } else {
    /* Full: recycle an address that is not blocked, longest unseen; failing
     * that, the one whose block ends first.  Never refuses a newcomer. */
    slot = -1;
    for (int i = 0; i < *count; i++) {
      bool bl = tab[i].blocked_until > now;
      if (bl) continue;
      if (slot < 0 || tab[i].last_seen < tab[slot].last_seen) slot = i;
    }
    if (slot < 0) {
      slot = 0;
      for (int i = 1; i < *count; i++)
        if (tab[i].blocked_until < tab[slot].blocked_until) slot = i;
    }
  }
  memset(&tab[slot], 0, sizeof(tab[slot]));
  snprintf(tab[slot].ip, sizeof(tab[slot].ip), "%s", ip);
  tab[slot].last_seen = now;
  tab[slot].win_start = now;
  return &tab[slot];
}

/* Block length for the next block of this address: the base, doubled for each
 * block already served within SSH_BLOCK_MEMORY, capped at SSH_BLOCK_MAX. */
static int start_block(ssh_ip_t *e, const hub_conn_cfg_t *cfg, time_t now) {
  if (e->last_block > 0 && now - e->last_block < SSH_BLOCK_MEMORY) {
    if (e->level < 30) e->level++;
  } else {
    e->level = 0;
  }
  long long secs = cfg->block;
  for (int i = 0; i < e->level && secs < SSH_BLOCK_MAX; i++) secs *= 2;
  if (secs > SSH_BLOCK_MAX) secs = SSH_BLOCK_MAX;
  e->blocked_until = now + (time_t)secs;
  e->last_block = now;
  e->conn_n = 0;
  e->fail_n = 0;
  return (int)secs;
}

/* A connection that sniffed as SSH.  False = refuse it.  *new_block is the
 * length of a block this very call started (0 otherwise). */
bool hub_ssh_table_connect(ssh_ip_t *tab, int *count, const hub_conn_cfg_t *cfg,
                           const char *ip, time_t now, int *new_block) {
  *new_block = 0;
  ssh_ip_t *e = ssh_find(tab, count, ip, now);
  if (e->blocked_until > now) return false;
  if (e->blocked_until > 0) {            /* expired: a fresh start */
    e->blocked_until = 0;
    e->conn_n = 0;
    e->fail_n = 0;
  }
  /* An address that logged into the console lately is not held to the connect
   * window (a tightened limit must not lock its admin out); a block it earned
   * by refused logins, checked above, still stands. */
  if (e->last_success > 0 && now - e->last_success < SSH_SUCCESS_MEMORY) return true;
  if (now - e->win_start >= cfg->connect_s) {
    e->win_start = now;
    e->conn_n = 0;
  }
  e->conn_n++;
  if (e->conn_n > cfg->connect_n) {
    *new_block = start_block(e, cfg, now);
    return false;
  }
  return true;
}

/* A console login by key succeeded from `ip`. */
void hub_ssh_table_success(ssh_ip_t *tab, int *count, const char *ip, time_t now) {
  ssh_find(tab, count, ip, now)->last_success = now;
}

const ssh_ip_t *hub_ssh_table_peek(const ssh_ip_t *tab, int count, const char *ip) {
  for (int i = 0; i < count; i++)
    if (strcmp(tab[i].ip, ip) == 0) return &tab[i];
  return NULL;
}

bool hub_ssh_table_recent_ok(const ssh_ip_t *tab, int count, const char *ip, time_t now) {
  const ssh_ip_t *e = hub_ssh_table_peek(tab, count, ip);
  return e && e->last_success > 0 && now - e->last_success < SSH_SUCCESS_MEMORY;
}

/* A refused SSH login (FAIL frame).  *new_block as above. */
void hub_ssh_table_failed(ssh_ip_t *tab, int *count, const hub_conn_cfg_t *cfg,
                          const char *ip, time_t now, int *new_block) {
  *new_block = 0;
  ssh_ip_t *e = ssh_find(tab, count, ip, now);
  if (e->blocked_until > now) return;
  if (e->blocked_until > 0) {
    e->blocked_until = 0;
    e->conn_n = 0;
    e->fail_n = 0;
  }
  if (e->fail_last > 0 && now - e->fail_last > cfg->authfail_s) e->fail_n = 0;
  e->fail_n++;
  e->fail_last = now;
  if (e->fail_n >= cfg->authfail_n) *new_block = start_block(e, cfg, now);
}

/* ==========================================================================
 * Eviction (console thread, on its own copies)
 * ========================================================================== */
/* All preauth slots taken and `new_ip` wants one: the victim is the oldest
 * login in progress of the address holding the most slots (the newcomer's own
 * address counts one more), so a flood from a few addresses cannot keep
 * anyone else out.  Ties go to the older session.  -1 when n == 0. */
int hub_ssh_evict_pick(const char *const *ips, const long long *start_ms, int n,
                       const char *new_ip) {
  int best = -1, best_cnt = 0;
  for (int i = 0; i < n; i++) {
    int cnt = (new_ip && strcmp(ips[i], new_ip) == 0) ? 1 : 0;
    for (int j = 0; j < n; j++)
      if (strcmp(ips[i], ips[j]) == 0) cnt++;
    if (best < 0 || cnt > best_cnt || (cnt == best_cnt && start_ms[i] < start_ms[best])) {
      best = i;
      best_cnt = cnt;
    }
  }
  return best;
}
