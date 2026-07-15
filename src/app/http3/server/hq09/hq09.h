#ifndef WIRED_HQ09_HQ09_H
#define WIRED_HQ09_HQ09_H

#include "common/bytes/span/span.h"

/** @file
 * quic-interop-runner's "hq-interop" ALPN (HTTP/0.9 over QUIC, not an IETF
 * protocol -- see quic.md's "Unless noted otherwise, test cases use
 * HTTP/0.9 for file transfers"). A client-initiated bidirectional stream
 * carries a single request line, "GET " + path + "\r\n" (verified against
 * quic-go's interop/http09 reference: client.go's `"GET " + req.URL.Path +
 * "\r\n"`, server.go's TrimRight("\r\n")/TrimRight(" ")/"GET /" check), and
 * the response is the file's raw bytes with no status line or headers
 * (server.go's responseWriter.WriteHeader is a no-op). */

/** Parse one hq-interop request line: trailing "\r\n" or "\n" and trailing
 * spaces are trimmed (matching the reference server's tolerance), then the
 * line must start with "GET /". Returns 1 with *path set to a view into
 * line (the bytes after "GET ", i.e. starting at the leading "/"), 0 if
 * the line does not start with "GET /" (any other method, or a path not
 * starting with "/").
 * @param line the raw stream bytes (request line, with or without a
 *   trailing newline)
 * @param path receives the path view (into line, no copy)
 * @return 1 on a valid GET request line, 0 otherwise */
int wired_hq09_parse_get(quic_span line, quic_span* path);

#endif
