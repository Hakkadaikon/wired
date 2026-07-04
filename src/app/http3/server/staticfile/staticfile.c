#include "app/http3/server/staticfile/staticfile.h"

#include "common/bytes/util/bytes.h"

/* 1 if path[i] is '/' or path is ending there (start/end-of-segment). */
static int staticfile_is_boundary(const char *path, usz i) {
  return path[i] == 0 || path[i] == '/';
}

/* 1 if path[i..i+2) is a ".." segment: preceded by '/' or start-of-string,
 * followed by '/' or end-of-string. */
static int staticfile_is_dotdot_at(const char *path, usz i) {
  if (i > 0 && !staticfile_is_boundary(path, i - 1)) return 0;
  return staticfile_is_boundary(path, i + 2);
}

/* 1 if path[i..) starts a ".." segment. */
static int staticfile_dotdot_here(const char *path, usz i) {
  if (path[i] != '.' || path[i + 1] != '.') return 0;
  return staticfile_is_dotdot_at(path, i);
}

int wired_staticfile_has_traversal(const char *path) {
  usz n = quic_cstr_len(path);
  for (usz i = 0; i + 1 < n; i++)
    if (staticfile_dotdot_here(path, i)) return 1;
  return 0;
}

/* Append src (NUL-terminated) to out at *off, capped at cap (including the
 * final NUL). Returns 1 on success, 0 if it would not fit. */
static int staticfile_append(char *out, usz cap, usz *off, const char *src) {
  usz i = 0;
  for (; src[i]; i++) {
    if (*off + 1 >= cap) return 0;
    out[(*off)++] = src[i];
  }
  out[*off] = 0;
  return 1;
}

/* 1 if reqpath names a directory: empty, or ends in "/". */
static int staticfile_is_dir(const char *reqpath, usz rlen) {
  if (rlen == 0) return 1;
  return reqpath[rlen - 1] == '/';
}

/* Append the index file name, inserting a "/" first when reqpath was empty
 * (root alone has no separator to reuse). */
static int staticfile_append_index(
    char *out, usz cap, usz *off, usz rlen, const char *index) {
  if (rlen == 0 && !staticfile_append(out, cap, off, "/")) return 0;
  return staticfile_append(out, cap, off, index);
}

/* Append root and reqpath into out; the shared prefix of every result. Rejects
 * traversal first, so the caller has one guard instead of two. */
static int staticfile_append_base(
    char *out, usz cap, usz *off, const char *root, const char *reqpath) {
  if (wired_staticfile_has_traversal(reqpath)) return 0;
  if (!staticfile_append(out, cap, off, root)) return 0;
  return staticfile_append(out, cap, off, reqpath);
}

int wired_staticfile_resolve(
    const char *root,
    const char *reqpath,
    const char *index,
    char       *out,
    usz         outcap) {
  usz off  = 0;
  usz rlen = quic_cstr_len(reqpath);
  if (!staticfile_append_base(out, outcap, &off, root, reqpath)) return 0;
  if (!staticfile_is_dir(reqpath, rlen)) return 1;
  return staticfile_append_index(out, outcap, &off, rlen, index);
}
