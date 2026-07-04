#include "app/http3/server/mimetype/mimetype.h"

#include "common/bytes/util/bytes.h"

#define MIMETYPE_DEFAULT "application/octet-stream"

/* Extension -> Content-Type table. Exact match only (case-sensitive); YAGNI
 * for a fuller MIME database. */
typedef struct {
  const char *ext;
  const char *content_type;
} mimetype_entry;

static const mimetype_entry MIMETYPE_TABLE[] = {
    {"html", "text/html"},
    {"css", "text/css"},
    {"js", "text/javascript"},
    {"json", "application/json"},
    {"txt", "text/plain"},
    {"png", "image/png"},
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
};
#define MIMETYPE_TABLE_LEN \
  (sizeof(MIMETYPE_TABLE) / sizeof(MIMETYPE_TABLE[0]))

/* 1 if a[i] mismatches ext at position i, or ext ends there (a run short). */
static int mimetype_ext_mismatch(const char *a, const char *ext, usz i) {
  return ext[i] == 0 || a[i] != ext[i];
}

/* 1 if a[0..n) equals the NUL-terminated ext exactly. */
static int mimetype_ext_eq(const char *a, usz n, const char *ext) {
  usz i = 0;
  for (; i < n; i++)
    if (mimetype_ext_mismatch(a, ext, i)) return 0;
  return ext[i] == 0;
}

/* Track the last '.' seen in the current path segment: reset to "none" (n) at
 * each '/', recorded at each '.'. */
static void mimetype_track_dot(const char *path, usz i, usz n, usz *dot) {
  if (path[i] == '/') *dot = n;
  if (path[i] == '.') *dot = i;
}

/* Scan path for the last '.' in its final segment. Returns n (no extension)
 * when none is found. */
static usz mimetype_last_dot(const char *path, usz n) {
  usz dot = n;
  for (usz i = 0; i < n; i++) mimetype_track_dot(path, i, n, &dot);
  return dot;
}

/* Find path's extension: the substring after the last '.' in the final path
 * segment. Returns its length via *len; the extension starts at the returned
 * pointer. Returns 0 (len 0) when there is no '.' in the final segment, or
 * the '.' is the segment's last character. */
static const char *mimetype_find_ext(const char *path, usz *len) {
  usz n   = quic_cstr_len(path);
  usz dot = mimetype_last_dot(path, n);
  *len    = 0;
  if (dot == n || dot + 1 == n) return 0;
  *len = n - dot - 1;
  return path + dot + 1;
}

/* Look up ext[0..len) in the table. Returns the Content-Type, or 0 if none
 * matches. */
static const char *mimetype_lookup(const char *ext, usz len) {
  for (usz i = 0; i < MIMETYPE_TABLE_LEN; i++)
    if (mimetype_ext_eq(ext, len, MIMETYPE_TABLE[i].ext))
      return MIMETYPE_TABLE[i].content_type;
  return 0;
}

const char *wired_mimetype_for_path(const char *path) {
  usz         len;
  const char *ext    = mimetype_find_ext(path, &len);
  const char *result = ext ? mimetype_lookup(ext, len) : 0;
  return result ? result : MIMETYPE_DEFAULT;
}
