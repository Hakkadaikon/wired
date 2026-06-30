#ifndef QUIC_LEGACY_FIELDS_H
#define QUIC_LEGACY_FIELDS_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.2: TLS 1.3 freezes the ClientHello legacy fields. legacy_version
 * MUST be 0x0303, legacy_compression_methods MUST be a single null (0x01 0x00),
 * and legacy_session_id is 0..32 bytes (echoed by the server in ServerHello). */

/* Validate the legacy fields of the ClientHello handshake message ch_msg (len
 * bytes, including the 4-byte handshake header). Returns 1 if legacy_version is
 * 0x0303 and compression is the single null method, 0 on any violation or if
 * the message is truncated/not a ClientHello. */
int quic_legacy_check_client_hello(const u8 *ch_msg, usz len);

/* Locate legacy_session_id in the ClientHello ch_msg (len bytes). On success
 * sets *sid to the session_id bytes (or ch_msg+offset with *sid_len 0 when
 * empty) and *sid_len to its length (0..32), returning 1. Returns 0 if the
 * message is truncated or not a ClientHello. */
int quic_legacy_session_id(const u8 *ch_msg, usz len, const u8 **sid,
                           u8 *sid_len);

#endif
