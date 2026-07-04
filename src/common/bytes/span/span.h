#ifndef QUIC_SPAN_H
#define QUIC_SPAN_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * Value-type views that fold the SDK's recurring argument shapes into single
 * parameters, keeping every function at <=3 args without a calling cost:
 *
 *   (const u8 *p, usz n)            -> quic_span   (by value: 16 bytes, two
 *   (u8 *p, usz n)                  -> quic_mspan   registers under SysV, the
 *                                                   same as the loose pair)
 *   (u8 *out, usz cap, usz *out_len)-> quic_obuf *  (one register instead of
 *                                                   three; callee fills .len)
 *
 * These are views, not owners: a span never copies and never frees. The
 * caller's buffer must stay alive for as long as the span (or anything the
 * span was handed to) is in use. Build them with the quic_span_of /
 * quic_mspan_of / quic_obuf_of constructors below.
 */

/**
 * Read-only view of a byte range.
 *
 * Wraps a `(const u8 *, length)` pair by value. Construct with
 * quic_span_of(); pass an empty input as `quic_span_of(0, 0)` (also written
 * `{0, 0}`). The pointed-to bytes are borrowed, never copied.
 */
typedef struct {
  const u8* p; /**< first byte of the viewed range (not owned) */
  usz       n; /**< number of readable bytes at p */
} quic_span;

/**
 * Mutable view of a byte range.
 *
 * Same shape as quic_span but writable: used for fixed-size outputs where
 * the callee fills exactly `n` bytes (e.g. a key or digest buffer).
 * Construct with quic_mspan_of().
 */
typedef struct {
  u8* p; /**< first byte of the writable range (not owned) */
  usz n; /**< number of writable bytes at p */
} quic_mspan;

/**
 * Growing output buffer view for variable-length results.
 *
 * Wraps `(u8 *out, usz cap, usz *out_len)` in one parameter: the caller
 * provides storage and capacity via quic_obuf_of(), the callee appends and
 * advances `len`. After the call, `p[0..len)` holds the produced bytes.
 */
typedef struct {
  u8* p;   /**< caller-provided storage (not owned) */
  usz cap; /**< capacity of p in bytes */
  usz len; /**< bytes written so far; the callee advances this */
} quic_obuf;

/**
 * Make a read-only span over p[0..n).
 *
 * The span borrows p; the buffer must outlive every use of the returned
 * value. Example: `quic_span msg = quic_span_of(buf, buf_len);`
 *
 * @param p first byte of the range (may be 0 when n is 0)
 * @param n number of readable bytes
 * @return the view as a value type
 */
static inline quic_span quic_span_of(const u8* p, usz n) {
  quic_span s = {p, n};
  return s;
}

/**
 * Make a mutable span over p[0..n).
 *
 * The span borrows p; the buffer must outlive every use of the returned
 * value. Example: `quic_mspan out = quic_mspan_of(key, sizeof key);`
 *
 * @param p first byte of the writable range
 * @param n number of writable bytes
 * @return the view as a value type
 */
static inline quic_mspan quic_mspan_of(u8* p, usz n) {
  quic_mspan s = {p, n};
  return s;
}

/**
 * Make an output buffer over p[0..cap) with len starting at 0.
 *
 * The buffer borrows p; the storage must outlive every use of the returned
 * value. Pass its address to the producing call and read `.len` afterwards:
 * `quic_obuf ob = quic_obuf_of(buf, sizeof buf);` ... use `ob.len`.
 *
 * @param p   caller-provided storage
 * @param cap capacity of p in bytes
 * @return the buffer view with len = 0
 */
static inline quic_obuf quic_obuf_of(u8* p, usz cap) {
  quic_obuf b = {p, cap, 0};
  return b;
}

#endif
