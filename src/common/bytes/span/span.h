#ifndef QUIC_SPAN_H
#define QUIC_SPAN_H

#include "common/platform/sys/syscall.h"

/* Value-type views that fold the SDK's recurring argument shapes into single
 * parameters, keeping every function at <=3 args without a calling cost:
 *
 *   (const u8 *p, usz n)            -> quic_span   (by value: 16 bytes, two
 *   (u8 *p, usz n)                  -> quic_mspan   registers under SysV, the
 *                                                   same as the loose pair)
 *   (u8 *out, usz cap, usz *out_len)-> quic_obuf *  (one register instead of
 *                                                   three; callee fills .len)
 */

typedef struct {
  const u8 *p;
  usz       n;
} quic_span;

typedef struct {
  u8 *p;
  usz n;
} quic_mspan;

typedef struct {
  u8 *p;
  usz cap;
  usz len;
} quic_obuf;

static inline quic_span quic_span_of(const u8 *p, usz n) {
  quic_span s = {p, n};
  return s;
}

static inline quic_mspan quic_mspan_of(u8 *p, usz n) {
  quic_mspan s = {p, n};
  return s;
}

static inline quic_obuf quic_obuf_of(u8 *p, usz cap) {
  quic_obuf b = {p, cap, 0};
  return b;
}

#endif
