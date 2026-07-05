#ifndef QUIC_CC_CUBIC_H
#define QUIC_CC_CUBIC_H

#include "common/platform/sys/syscall.h"

/* RFC 9438: CUBIC window growth, integer-only (no floats in this SDK).
 * Windows are in segments, times in milliseconds. C = 0.4, beta = 0.7. */

/* RFC 9438 4.2: K = cbrt(W_max * (1 - beta) / C) seconds, returned in ms.
 * (1-beta)/C = 0.75, so K_ms = cbrt(W_max * 0.75e9). */
u64 quic_cubic_k_ms(u64 w_max_seg);

/* RFC 9438 4.1: W_cubic(t) = C*(t - K)^3 + W_max, in segments, floored at 0.
 * t_ms is clamped so the cube stays within 64-bit range (~100s past K). */
u64 quic_cubic_w(u64 t_ms, u64 k_ms, u64 w_max_seg);

/* RFC 9438 4.6 fast convergence: when the window at loss is below the
 * previous W_max, remember a further-reduced W_max (W * (1+beta)/2 = 0.85W);
 * otherwise W itself becomes the new W_max. */
u64 quic_cubic_wmax_fastconv(u64 w_seg, u64 prev_wmax_seg);

#endif
