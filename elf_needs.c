/* elf_needs.c — see elf_needs.h.  Byte-identical in irchub and ircbot. */
#include "elf_needs.h"

#include <ctype.h>
#include <fcntl.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#define EN_DIRS_MAX     64
#define EN_DIR_MAX      255
#define EN_CONF_FILES   32
#define EN_FILE_MAX     (256L * 1024 * 1024) /* a library larger than this is not read */
#define EN_SECT_MAX     4096                 /* section headers                         */
#define EN_TABLE_MAX    (4L * 1024 * 1024)   /* verdef section bytes; names are read one
                                              * at a time, so the string table is uncapped */
#define SHT_GNU_VERDEF  0x6ffffffdU
#define VER_FLG_BASE    0x1

/* ---- Where the loader looks ------------------------------------------- */

typedef struct {
  char d[EN_DIRS_MAX][EN_DIR_MAX + 1];
  int n;
} en_dirs_t;

static void en_dir_add(en_dirs_t *ds, const char *p, size_t len) {
  if (len == 0 || len > EN_DIR_MAX || p[0] != '/' || ds->n >= EN_DIRS_MAX) return;
  for (int i = 0; i < ds->n; i++)
    if (strlen(ds->d[i]) == len && memcmp(ds->d[i], p, len) == 0) return;
  memcpy(ds->d[ds->n], p, len);
  ds->d[ds->n][len] = '\0';
  ds->n++;
}

/* One ld.so.conf file: a directory per line, "include <glob>" one level down. */
static void en_conf_read(en_dirs_t *ds, const char *path, int depth, int *files) {
  if (depth > 1 || *files >= EN_CONF_FILES) return;
  (*files)++;
  FILE *f = fopen(path, "r");
  if (!f) return;
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    char *h = strchr(line, '#');
    if (h) *h = '\0';
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    size_t l = strcspn(p, "\r\n");
    while (l && (p[l - 1] == ' ' || p[l - 1] == '\t')) l--;
    p[l] = '\0';
    if (!l) continue;
    if (strncmp(p, "include", 7) == 0 && (p[7] == ' ' || p[7] == '\t')) {
      char *g = p + 8;
      while (*g == ' ' || *g == '\t') g++;
      glob_t gl;
      if (*g == '/' && glob(g, 0, NULL, &gl) == 0) {
        for (size_t i = 0; i < gl.gl_pathc; i++) en_conf_read(ds, gl.gl_pathv[i], depth + 1, files);
        globfree(&gl);
      }
      continue;
    }
    en_dir_add(ds, p, l);
  }
  fclose(f);
}

static const char *en_triplet(void) {
  struct utsname u;
  if (uname(&u) != 0) return NULL;
  if (strcmp(u.machine, "x86_64") == 0) return "x86_64-linux-gnu";
  if (strcmp(u.machine, "aarch64") == 0) return "aarch64-linux-gnu";
  if (strncmp(u.machine, "armv7", 5) == 0) return "arm-linux-gnueabihf";
  if (strcmp(u.machine, "i686") == 0 || strcmp(u.machine, "i386") == 0) return "i386-linux-gnu";
  return NULL;
}

static void en_dirs(en_dirs_t *ds) {
  ds->n = 0;
  const char *lp = getenv("LD_LIBRARY_PATH");
  for (const char *p = lp; p && *p;) {
    const char *c = strchr(p, ':');
    size_t l = c ? (size_t)(c - p) : strlen(p);
    en_dir_add(ds, p, l);
    p = c ? c + 1 : p + l;
  }
  int files = 0;
  en_conf_read(ds, "/etc/ld.so.conf", 0, &files);
  const char *t = en_triplet();
  char b[EN_DIR_MAX + 1];
  if (t) {
    snprintf(b, sizeof(b), "/lib/%s", t);
    en_dir_add(ds, b, strlen(b));
    snprintf(b, sizeof(b), "/usr/lib/%s", t);
    en_dir_add(ds, b, strlen(b));
  }
  static const char *const std_dirs[] = {"/lib64", "/usr/lib64", "/lib", "/usr/lib"};
  for (size_t i = 0; i < sizeof(std_dirs) / sizeof(std_dirs[0]); i++)
    en_dir_add(ds, std_dirs[i], strlen(std_dirs[i]));
}

/* A library name: [A-Za-z0-9._+-], no '/', 1..EN_NAME_MAX. */
static bool en_soname_ok(const char *s, size_t n) {
  if (n == 0 || n > EN_NAME_MAX || s[0] == '.') return false;
  for (size_t i = 0; i < n; i++)
    if (!(isalnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '_' || s[i] == '+' || s[i] == '-'))
      return false;
  return true;
}

bool en_find_lib(const char *soname, char *out, size_t out_size) {
  if (!en_soname_ok(soname, strlen(soname))) return false;
  en_dirs_t ds;
  en_dirs(&ds);
  for (int i = 0; i < ds.n; i++) {
    char p[EN_DIR_MAX + EN_NAME_MAX + 2];
    snprintf(p, sizeof(p), "%s/%s", ds.d[i], soname);
    struct stat st;
    if (stat(p, &st) == 0 && S_ISREG(st.st_mode) && access(p, R_OK) == 0) {
      snprintf(out, out_size, "%s", p);
      return true;
    }
  }
  return false;
}

/* ---- The version-definition table -------------------------------------- */

static uint64_t en_le(const unsigned char *b, int n) {
  uint64_t v = 0;
  for (int i = n - 1; i >= 0; i--) v = (v << 8) | b[i];
  return v;
}

static bool en_pread(int fd, void *buf, size_t n, uint64_t off, uint64_t fsize) {
  if (off > fsize || n > fsize - off) return false;
  ssize_t r = pread(fd, buf, n, (off_t)off);
  return r >= 0 && (size_t)r == n;
}

int en_verdefs(const char *path, char names[][EN_NAME_MAX + 1], int max) {
  int rc = -1, n = 0;
  unsigned char *sh = NULL, *vd = NULL;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 64 || st.st_size > EN_FILE_MAX)
    goto out;
  uint64_t fsize = (uint64_t)st.st_size;
  unsigned char eh[64];
  if (!en_pread(fd, eh, sizeof(eh), 0, fsize)) goto out;
  if (memcmp(eh, "\177ELF", 4) != 0 || eh[5] != 1 /* little-endian */) goto out;
  bool is64 = eh[4] == 2;
  if (!is64 && eh[4] != 1) goto out;
  uint64_t shoff = is64 ? en_le(eh + 0x28, 8) : en_le(eh + 0x20, 4);
  uint64_t shentsize = is64 ? en_le(eh + 0x3A, 2) : en_le(eh + 0x2E, 2);
  uint64_t shnum = is64 ? en_le(eh + 0x3C, 2) : en_le(eh + 0x30, 2);
  if (shentsize != (is64 ? 64U : 40U) || shnum == 0 || shnum > EN_SECT_MAX) goto out;
  sh = malloc((size_t)(shnum * shentsize));
  if (!sh || !en_pread(fd, sh, (size_t)(shnum * shentsize), shoff, fsize)) goto out;
  /* Section i: type, offset, size, link, info. */
#define SH(i, f64, f32, w64, w32) \
  (is64 ? en_le(sh + (i) * shentsize + (f64), (w64)) : en_le(sh + (i) * shentsize + (f32), (w32)))
  uint64_t vdi = shnum;
  for (uint64_t i = 0; i < shnum; i++)
    if (SH(i, 4, 4, 4, 4) == SHT_GNU_VERDEF) {
      vdi = i;
      break;
    }
  if (vdi == shnum) {
    rc = 0; /* defines no versions */
    goto out;
  }
  uint64_t vdoff = SH(vdi, 24, 16, 8, 4), vdsize = SH(vdi, 32, 20, 8, 4);
  uint64_t link = SH(vdi, 40, 24, 4, 4), count = SH(vdi, 44, 28, 4, 4);
  if (link >= shnum || vdsize > EN_TABLE_MAX || count > EN_DEFS_MAX * 4) goto out;
  uint64_t stroff = SH(link, 24, 16, 8, 4), strsize = SH(link, 32, 20, 8, 4);
#undef SH
  if (strsize == 0 || stroff > fsize || strsize > fsize - stroff) goto out;
  vd = malloc((size_t)vdsize + 1);
  if (!vd || !en_pread(fd, vd, (size_t)vdsize, vdoff, fsize)) goto out;
  /* Verdef: version u16, flags u16, ndx u16, cnt u16, hash u32, aux u32,
   * next u32 (20 bytes); Verdaux: name u32, next u32. */
  uint64_t at = 0;
  for (uint64_t k = 0; k < count; k++) {
    if (vdsize < 20 || at > vdsize - 20) goto out;
    const unsigned char *v = vd + at;
    uint64_t flags = en_le(v + 2, 2), cnt = en_le(v + 6, 2);
    uint64_t aux = en_le(v + 12, 4), next = en_le(v + 16, 4);
    if (cnt > 0) {
      if (aux > vdsize - at || vdsize - at - aux < 8) goto out;
      uint64_t name = en_le(vd + at + aux, 4);
      if (name >= strsize) goto out;
      /* Just this name: up to EN_NAME_MAX + 1 bytes, never past the table. */
      char nm[EN_NAME_MAX + 2];
      uint64_t take = strsize - name < sizeof(nm) - 1 ? strsize - name : sizeof(nm) - 1;
      if (!en_pread(fd, nm, (size_t)take, stroff + name, fsize)) goto out;
      nm[take] = '\0';
      size_t nl = strlen(nm);
      if (!(flags & VER_FLG_BASE) && nl > 0 && nl <= EN_NAME_MAX && n < max) {
        memcpy(names[n], nm, nl + 1);
        n++;
      }
    }
    if (next == 0) break;
    if (next > vdsize - at) goto out;
    at += next;
  }
  rc = n;
out:
  free(sh);
  free(vd);
  close(fd);
  return rc;
}

/* ---- The check ----------------------------------------------------------- */

/* A version name: [A-Za-z0-9._], 1..EN_NAME_MAX. */
static bool en_ver_ok(const char *s, size_t n) {
  if (n == 0 || n > EN_NAME_MAX) return false;
  for (size_t i = 0; i < n; i++)
    if (!(isalnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '_')) return false;
  return true;
}

bool en_check(const char *needs, char *why, size_t why_size) {
  if (why && why_size) why[0] = '\0';
  if (!needs || !needs[0] || strcmp(needs, "-") == 0) return true;
  /* Parse all of it first: a list we cannot read decides nothing. */
  size_t nl = strlen(needs);
  if (nl > 1024) return true;
  char (*defs)[EN_NAME_MAX + 1] = calloc(EN_DEFS_MAX, sizeof(*defs));
  if (!defs) return true;
  bool ok = true;
  for (const char *p = needs; *p && ok;) {
    const char *end = strchr(p, ',');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    const char *at = memchr(p, '@', len);
    size_t sl = at ? (size_t)(at - p) : len;
    char soname[EN_NAME_MAX + 1];
    if (!en_soname_ok(p, sl)) break; /* unreadable: decide nothing */
    memcpy(soname, p, sl);
    soname[sl] = '\0';
    char path[EN_DIR_MAX + EN_NAME_MAX + 2];
    if (!en_find_lib(soname, path, sizeof(path))) {
      if (why) snprintf(why, why_size, "%s (not found on this host)", soname);
      ok = false;
      break;
    }
    if (at && !(len - sl - 1 == 1 && at[1] == '-')) {
      int nd = en_verdefs(path, defs, EN_DEFS_MAX);
      for (const char *v = at + 1; v < p + len && ok;) {
        const char *plus = memchr(v, '+', (size_t)(p + len - v));
        size_t vl = plus ? (size_t)(plus - v) : (size_t)(p + len - v);
        if (!en_ver_ok(v, vl)) break;
        bool have = false;
        for (int d = 0; d < nd && !have; d++) have = strlen(defs[d]) == vl && memcmp(defs[d], v, vl) == 0;
        if (!have) {
          if (why)
            snprintf(why, why_size, "%s with %.*s (not provided by %s)", soname, (int)vl, v, path);
          ok = false;
        }
        v += vl + (plus ? 1 : 0);
      }
    }
    p += len + (end ? 1 : 0);
  }
  free(defs);
  return ok;
}

/* "2.43" > "2.9": dot-separated parts compared as numbers. */
static int en_glibc_cmp(const char *a, const char *b) {
  for (;;) {
    unsigned long x = 0, y = 0;
    while (isdigit((unsigned char)*a)) x = x * 10 + (unsigned long)(*a++ - '0');
    while (isdigit((unsigned char)*b)) y = y * 10 + (unsigned long)(*b++ - '0');
    if (x != y) return x < y ? -1 : 1;
    if (*a != '.' || *b != '.') return (*a == '.') - (*b == '.');
    a++;
    b++;
  }
}

bool en_glibc(char *out, size_t out_size) {
  char path[EN_DIR_MAX + EN_NAME_MAX + 2];
  if (!en_find_lib("libc.so.6", path, sizeof(path))) return false;
  char (*defs)[EN_NAME_MAX + 1] = calloc(EN_DEFS_MAX, sizeof(*defs));
  if (!defs) return false;
  int nd = en_verdefs(path, defs, EN_DEFS_MAX);
  const char *best = NULL;
  for (int i = 0; i < nd; i++) {
    const char *v = defs[i];
    if (strncmp(v, "GLIBC_", 6) != 0 || !isdigit((unsigned char)v[6])) continue;
    bool num = true;
    for (const char *c = v + 6; *c; c++)
      if (!isdigit((unsigned char)*c) && *c != '.') num = false;
    if (num && (!best || en_glibc_cmp(v + 6, best + 6) > 0)) best = v;
  }
  if (best) snprintf(out, out_size, "%s", best + 6);
  free(defs);
  return best != NULL;
}
