#ifndef WIRED_MIMETYPE_MIMETYPE_H
#define WIRED_MIMETYPE_MIMETYPE_H

/** @file
 * Infer an HTTP Content-Type from a static file's path, by its extension
 * (the substring after the last '.' in the final path segment). */

/** Return the Content-Type for path's extension, or "application/octet-
 * stream" when the extension is absent or unrecognized. The returned string
 * is a static constant; the caller must not free it.
 * @param path NUL-terminated file path (request path or resolved file path)
 * @return NUL-terminated Content-Type string */
const char *wired_mimetype_for_path(const char *path);

#endif
