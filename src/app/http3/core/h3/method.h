#ifndef QUIC_H3_METHOD_H
#define QUIC_H3_METHOD_H

#include "common/bytes/span/span.h"

/* RFC 9110 9.1: the registered HTTP methods (GET, HEAD, POST, PUT, DELETE,
 * CONNECT, OPTIONS, TRACE) plus PATCH (RFC 5789) -- the set an origin server
 * must recognize before it can even ask whether a given resource allows it.
 * A method outside this set is unrecognized (RFC 9110 9.1: 501 Not
 * Implemented). */

/* 1 if method is one of the RFC 9110 9.1 registered methods (case-sensitive,
 * RFC 9110 9.1: method tokens are case-sensitive). */
int quic_h3_method_is_known(quic_span method);

/* 1 if method is recognized AND this server actually serves it for a request
 * reaching the application handler (RFC 9110 9.1: 405 Method Not Allowed for
 * a recognized-but-unsupported method). wired has no per-resource routing --
 * every request reaches the same single application handler -- so this is a
 * server-wide allow set rather than a per-resource one: GET, HEAD, POST, PUT,
 * DELETE, OPTIONS, CONNECT (a plain CONNECT that failed Extended CONNECT
 * dispatch, RFC 9220 3, already falls through to the application handler --
 * a pre-existing, separately tested behavior this gate must not change).
 * TRACE (RFC 9110 9.3.8, a diagnostic echo this SDK does not implement) is
 * the only recognized-but-not-allowed method. */
int quic_h3_method_is_allowed(quic_span method);

#endif
