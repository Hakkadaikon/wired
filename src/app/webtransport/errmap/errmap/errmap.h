#ifndef WTERRMAP_H
#define WTERRMAP_H

#include "common/platform/sys/syscall.h"

/* WebTransport application error code <-> HTTP/3-level error code mapping
 * (draft-ietf-webtrans-http3-15 8.2). An application error code n (any u32)
 * is packed into a reserved HTTP/3 error-code range [first, last] so it
 * survives being carried in an HTTP/3-level error-code field, skipping the
 * codepoints reserved for greasing (RFC 9114 7.2.9 style: every 0x1f-th
 * value starting at 0x21 relative to first is reserved). */

/* Forward: application error code -> HTTP/3-level error code. n may be any
 * u32 value; the whole domain maps into [first, last]. */
u64 wired_wterrmap_to_http3(u32 n);

/* Reverse: HTTP/3-level error code -> application error code. Returns 1 and
 * sets *n_out on success. Returns 0 if h falls outside [first, last] or
 * lands on a reserved codepoint (defends against arbitrary/adversarial h
 * values arriving from the wire; a value produced by
 * wired_wterrmap_to_http3 never triggers this rejection). */
int wired_wterrmap_from_http3(u64 h, u32* n_out);

/* draft-ietf-webtrans-http3-16 9.5/6: named WebTransport-defined HTTP/3
 * error codes. All five below are registered in the IANA "HTTP/3 Error
 * Code" registry (SS9.5) and are protocol-level codes sent RAW on the wire,
 * never through wired_wterrmap_to_http3 -- that function is only for
 * WebTransport APPLICATION error codes (arbitrary u32 values an app chooses),
 * which is a disjoint concern. Defined here (rather than at each event site)
 * because most do not yet have a live trigger in this SDK:
 *
 * - WT_BUFFERED_STREAM_REJECTED: reset a stream that arrived before session
 *   establishment and found the pre-establishment buffer full (session/
 *   session.h wired_wt_session_offer_stream documents this on its 0 return).
 *   Live: srvrun.c's srvrun_reject_wt_slot.
 * - WT_SESSION_GONE: a stream/datagram referenced an already-closed session,
 *   or signals the endpoint stopped reading the CONNECT stream. Live:
 *   srvrun.c's srvrun_close_wt_session_slot callers.
 * - WT_FLOW_CONTROL_ERROR: a WebTransport-level flow-control violation.
 * - WT_ALPN_ERROR: application-protocol negotiation over WebTransport
 *   failed. Dormant: WT-Available-Protocols/WT-Protocol negotiation is out
 *   of scope.
 * - WT_REQUIREMENTS_NOT_MET: the peer's SETTINGS/transport parameters did
 *   not actually satisfy WebTransport's requirements. Dormant: SETTINGS/
 *   transport-parameter completeness checking is not implemented.
 */
#define WTERR_BUFFERED_STREAM_REJECTED 0x3994bd84u
#define WTERR_SESSION_GONE 0x170d7b68u
#define WTERR_FLOW_CONTROL_ERROR 0x045d4487u
#define WTERR_ALPN_ERROR 0x0817b3ddu
#define WTERR_REQUIREMENTS_NOT_MET 0x212c0d48u

#endif
