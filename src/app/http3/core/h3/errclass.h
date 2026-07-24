#ifndef QUIC_H3_ERRCLASS_H
#define QUIC_H3_ERRCLASS_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 8.1. HTTP/3 error codes 0x0100..0x0110 are defined by this
 * specification ("known"). Values of the form 0x1f*N + 0x21 are reserved for
 * grease and have no semantics. Any other value is left for application or
 * future use. A reserved code is not a known code. */

/* Whether code is an error code defined in RFC 9114 8.1 (0x0100..0x0110). */
int quic_h3_error_is_known(u64 code);

/* Whether code is a reserved (grease) error point, per RFC 9114 8.1. */
int quic_h3_error_is_reserved(u64 code);

/* RFC 9114 8.1 / 9114-077: when a sender would close with H3_NO_ERROR, it
 * SHOULD select a reserved (grease) error code instead with some
 * probability, so a receiver's handling of an unrecognized-but-valid code
 * (9114-075: treated as equivalent to H3_NO_ERROR) gets exercised on the
 * wire rather than merely tolerated in theory. This function is the
 * deterministic half of that: if code is H3_NO_ERROR and grease_id is
 * non-zero, returns grease_id; otherwise returns code unchanged (grease_id
 * is ignored for every other code -- greasing only ever substitutes for
 * H3_NO_ERROR). The probabilistic decision of whether/which grease_id to
 * offer belongs to the caller (mirrors quic_h3settings_in.grease_id's split,
 * settings_build.h), keeping this function itself trivial to test.
 * @param code the error code the sender was about to use
 * @param grease_id 0 to send code as-is, or a reserved (0x1f*N + 0x21 form)
 *   identifier to substitute when code is QUIC_H3_NO_ERROR
 * @return the error code to actually send */
u64 quic_h3_error_send_value(u64 code, u64 grease_id);

#endif
