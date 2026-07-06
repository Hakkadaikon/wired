#ifndef QUIC_WTERRMAP_H
#define QUIC_WTERRMAP_H

#include "common/platform/sys/syscall.h"

/* WebTransport application error code <-> HTTP/3-level error code mapping
 * (draft-ietf-webtrans-http3-15 8.2). An application error code n (any u32)
 * is packed into a reserved HTTP/3 error-code range [first, last] so it
 * survives being carried in an HTTP/3-level error-code field, skipping the
 * codepoints reserved for greasing (RFC 9114 7.2.9 style: every 0x1f-th
 * value starting at 0x21 relative to first is reserved). */

/* Forward: application error code -> HTTP/3-level error code. n may be any
 * u32 value; the whole domain maps into [first, last]. */
u64 quic_wterrmap_to_http3(u32 n);

/* Reverse: HTTP/3-level error code -> application error code. Returns 1 and
 * sets *n_out on success. Returns 0 if h falls outside [first, last] or
 * lands on a reserved codepoint (defends against arbitrary/adversarial h
 * values arriving from the wire; a value produced by
 * quic_wterrmap_to_http3 never triggers this rejection). */
int quic_wterrmap_from_http3(u64 h, u32* n_out);

#endif
