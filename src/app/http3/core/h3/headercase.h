#ifndef QUIC_H3_HEADERCASE_H
#define QUIC_H3_HEADERCASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.3. Field names in HTTP/3 MUST be lowercase. A field name that
 * contains an uppercase letter MUST be treated as malformed (H3_MESSAGE_ERROR).
 * Returns 1 if name (len bytes) contains no uppercase A-Z, 0 otherwise. */
int quic_h3_header_name_ok(const u8* name, usz len);

/* RFC 9114 10.3, RFC 9110 5.5. A field name or value that contains CR
 * (0x0d), LF (0x0a) or NUL (0x00) MUST be treated as malformed
 * (H3_MESSAGE_ERROR); such octets are unusable for request smuggling once
 * rejected outright. Returns 1 if buf (len bytes) contains none of them. */
int quic_h3_header_bytes_ok(const u8* buf, usz len);

/* RFC 9114 4.1 (Transfer-Encoding) and 4.2 (connection-specific fields):
 * neither has meaning in HTTP/3 -- a message carrying one of these field
 * names MUST be treated as malformed (H3_MESSAGE_ERROR). Returns 1 if
 * name (len bytes) is exactly one of the forbidden names, 0 otherwise. */
int quic_h3_header_name_forbidden(const u8* name, usz len);

/* RFC 9114 4.2: a TE field MUST NOT carry any value other than "trailers".
 * Returns 1 if value (len bytes) is exactly "trailers", 0 otherwise. */
int quic_h3_header_te_ok(const u8* value, usz len);

#endif
