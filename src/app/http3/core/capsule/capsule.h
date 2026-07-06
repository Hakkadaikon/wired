#ifndef QUIC_CAPSULE_CAPSULE_H
#define QUIC_CAPSULE_CAPSULE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9297 SS3.2 Capsule Protocol: a generic type+length+value envelope
 * carried over an HTTP Datagram-capable stream. This is the framing layer
 * only -- it knows nothing about any specific capsule type's payload
 * semantics (those, e.g. WebTransport's WT_CLOSE_SESSION, are a separate,
 * later domain layered on top of this codec).
 *
 * Wire format (RFC 9297 SS3.2):
 *   Capsule Type (i)    -- QUIC variable-length integer (RFC 9000 SS16)
 *   Capsule Length (i)  -- QUIC varint, length of Capsule Value in bytes
 *   Capsule Value (..)  -- exactly Capsule Length bytes
 */

/** Encode one capsule (type + length-prefixed value) into out.
 *
 * On failure (the encoding does not fit in out's remaining capacity),
 * out is left unmodified -- no partial bytes are written, so a caller
 * cannot mistake a failed encode for a valid partial one.
 *
 * @param out   destination buffer view; out->len is advanced on success
 * @param type  capsule type (QUIC varint range, <= 2^62-1)
 * @param value capsule value bytes (may be empty)
 * @return 1 on success, 0 if it doesn't fit (or type is out of varint range)
 */
int quic_capsule_encode(quic_obuf* out, u64 type, quic_span value);

/** Decode the next capsule starting at *at within data.
 *
 * On success, advances *at past the decoded capsule, sets *type and *value
 * (value is a view into data, valid only as long as data itself is), and
 * returns 1.
 *
 * Returns 0 if there is no complete capsule at *at: either not enough bytes
 * are present yet for the type/length varints, or fewer than the declared
 * Length bytes remain in data. This is NOT necessarily an error -- per
 * RFC 9297 a partial capsule at the end of currently-available stream data
 * simply means "wait for more data to arrive". The caller must use its own
 * context (e.g. whether FIN has already been seen with no more bytes
 * expected) to decide whether a 0 return means "benign, wait for more" or
 * "malformed, the stream ended mid-capsule". *at, *type, *value are left
 * unmodified on a 0 return.
 *
 * @param data  the buffer to decode from
 * @param at    in/out cursor offset within data
 * @param type  set to the decoded capsule type on success
 * @param value set to a view of the capsule value on success
 * @return 1 on success, 0 if incomplete or malformed
 */
int quic_capsule_decode(quic_span data, usz* at, u64* type, quic_span* value);

#endif
