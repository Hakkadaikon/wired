#ifndef QUIC_WTCAPSULE_WTCAPSULE_H
#define QUIC_WTCAPSULE_WTCAPSULE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-webtrans-http3-15 SS4.2: the two WebTransport-specific capsule
 * types layered on top of the generic RFC 9297 Capsule Protocol codec
 * (app/http3/core/capsule/capsule.h). This is the wire-format layer only --
 * it does not call into the session state machine (session/session.h)
 * itself; a caller decodes a capsule here and then drives the session
 * transition (e.g. wired_wt_session_drain) as a separate step.
 *
 * WT_CLOSE_SESSION (type 0x2843):
 *   Application Error Code (32)
 *   Application Error Message (..)  -- UTF-8, MUST NOT exceed 1024 bytes
 *
 * WT_DRAIN_SESSION (type 0x78ae): empty body (Length=0), purely a signal.
 *
 * Per-stream flow-control capsules (e.g. a hypothetical WT_MAX_STREAM_DATA /
 * WT_STREAM_DATA_BLOCKED) are intentionally NOT declared here and never will
 * be: the HTTP/3 WebTransport mapping (this draft) does not define them at
 * all -- they exist only in the sibling HTTP/2-based WebTransport mapping,
 * which this SDK does not implement. Per-stream flow control on HTTP/3 is
 * instead covered natively by QUIC's own MAX_STREAM_DATA frame at the
 * transport layer (already implemented outside this file). See
 * tasks/webtransport-plan.md WT-E-010. The two functions above
 * (encode/decode close, encode/decode drain) are, by design, the entire
 * WT capsule API surface -- there is no third capsule type to add here.
 */

/** Maximum WT_CLOSE_SESSION application error message length, in bytes
 * (draft-ietf-webtrans-http3-15 SS4.2). */
#define QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX 1024

/** Encode a WT_CLOSE_SESSION capsule (type 0x2843) into out.
 *
 * Rejects (returns 0, leaves out unmodified) if message.n exceeds
 * QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX -- this is a WebTransport wire-format
 * constraint, checked independently of whether out happens to have room.
 *
 * @param out             destination buffer view
 * @param app_error_code  32-bit application error code
 * @param message         UTF-8 error message, message.n <= 1024 (may be empty)
 * @return 1 on success, 0 if message is too long or it doesn't fit in out
 */
int quic_wtcapsule_encode_close(
    quic_obuf* out, u32 app_error_code, quic_span message);

/** Encode a WT_DRAIN_SESSION capsule (type 0x78ae, empty body) into out.
 * @param out destination buffer view
 * @return 1 on success, 0 if it doesn't fit in out
 */
int quic_wtcapsule_encode_drain(quic_obuf* out);

/** Attempt to decode the capsule at *at within data as a WT_CLOSE_SESSION.
 *
 * "Wrong type, don't consume" contract: if a complete capsule is present at
 * *at but its type is not 0x2843, this returns 0 and *at, *app_error_code,
 * *message are all left UNCHANGED -- so a caller can go on to try a
 * different decode_* function (e.g. quic_wtcapsule_decode_drain) at the
 * same, still-unconsumed offset. This differs from quic_capsule_decode
 * itself, which reports "no complete capsule yet" the same way it reports
 * "wrong type" would be reported here: both leave *at untouched, so the two
 * failure causes are indistinguishable to the caller by design (either way,
 * nothing was consumed).
 *
 * Also returns 0, *at unchanged, if the capsule IS type 0x2843 but
 * malformed: its value is too short to hold the 32-bit error code, or its
 * message exceeds QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX bytes.
 *
 * @param data            the buffer to decode from
 * @param at              in/out cursor offset within data
 * @param app_error_code  set to the decoded error code on success
 * @param message         set to a view of the error message on success
 * @return 1 on success, 0 otherwise (see above)
 */
int quic_wtcapsule_decode_close(
    quic_span data, usz* at, u32* app_error_code, quic_span* message);

/** Attempt to decode the capsule at *at within data as a WT_DRAIN_SESSION.
 * Same "wrong type / incomplete, don't consume" contract as
 * quic_wtcapsule_decode_close -- *at only advances on a confirmed
 * WT_DRAIN_SESSION capsule.
 * @param data the buffer to decode from
 * @param at   in/out cursor offset within data
 * @return 1 if a WT_DRAIN_SESSION capsule was present and consumed, 0 otherwise
 */
int quic_wtcapsule_decode_drain(quic_span data, usz* at);

#endif
