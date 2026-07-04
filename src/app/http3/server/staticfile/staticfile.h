#ifndef WIRED_STATICFILE_STATICFILE_H
#define WIRED_STATICFILE_STATICFILE_H

#include "common/platform/sys/syscall.h"

/** @file
 * Resolve an HTTP request path into a document-root-relative file path for
 * static file serving (quiche-server's --root/--index), rejecting path
 * traversal. Socket- and filesystem-free: string manipulation only, the
 * caller opens the resolved path (e.g. via wired_fio_read). */

/** 1 if path contains a ".." path-traversal segment: "/../", a leading
 * "../", or a trailing "/..". A ".." that is merely a substring of a longer
 * segment (e.g. "foo..bar.txt") is NOT flagged.
 * @param path NUL-terminated request path
 * @return 1 if a ".." segment is present, 0 otherwise */
int wired_staticfile_has_traversal(const char* path);

/** Resolve reqpath against root into out, rejecting traversal.
 *
 * root is always prefixed (no absolute-path double interpretation). If
 * reqpath is empty or ends in "/", index is appended as the file name
 * (e.g. root="/www", reqpath="/", index="index.html" -> "/www/index.html").
 *
 * @param root NUL-terminated document root, no trailing slash
 * @param reqpath NUL-terminated request path, e.g. "/foo/bar.txt"
 * @param index NUL-terminated index file name used when reqpath names a
 *   directory (empty or trailing "/")
 * @param out destination buffer for the resolved, NUL-terminated path
 * @param outcap capacity of out in bytes, including the NUL terminator
 * @return 1 on success; 0 if reqpath contains a ".." segment or the
 *   resolved path (with NUL) does not fit in outcap */
int wired_staticfile_resolve(
    const char* root,
    const char* reqpath,
    const char* index,
    char*       out,
    usz         outcap);

#endif
