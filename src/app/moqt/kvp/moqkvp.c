#include "app/moqt/kvp/moqkvp.h"

#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"

/* draft-ietf-moq-transport-19 1.4.3: Value is Length bytes when Type is
 * odd, a single varint when Type is even. */

/* Length is already read; check the 2^16-1 cap, then view the bytes. */
static int moqkvp_raw_body(wired_span buf, usz* at, u64 len, moqkvp* out) {
  if (len > QUIC_MOQKVP_MAX_LEN) return QUIC_MOQKVP_VIOLATION;
  if (buf.n - *at < len) return QUIC_MOQKVP_INSUFFICIENT;
  out->raw = wired_span_of(buf.p + *at, (usz)len);
  *at += (usz)len;
  return QUIC_MOQKVP_OK;
}

static int moqkvp_take_raw(wired_span buf, usz* at, moqkvp* out) {
  u64 len;
  if (!moqvi_take(buf, at, &len)) return QUIC_MOQKVP_INSUFFICIENT;
  return moqkvp_raw_body(buf, at, len, out);
}

static int moqkvp_take_value(wired_span buf, usz* at, moqkvp* out) {
  if (!out->is_raw)
    return moqvi_take(buf, at, &out->num) ? QUIC_MOQKVP_OK
                                          : QUIC_MOQKVP_INSUFFICIENT;
  return moqkvp_take_raw(buf, at, out);
}

/* Delta + value at *at; prev is read-only here so a failed take cannot
 * disturb the caller's running Type. */
static int moqkvp_take_at(wired_span buf, usz* at, u64 prev, moqkvp* out) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) return QUIC_MOQKVP_INSUFFICIENT;
  /* 1.4.3: prev + Delta MUST NOT exceed 2^64-1 (u64 addition would wrap) */
  if (delta > (u64)-1 - prev) return QUIC_MOQKVP_VIOLATION;
  out->type   = prev + delta;
  out->is_raw = (int)(out->type & 1);
  return moqkvp_take_value(buf, at, out);
}

int moqkvp_take(wired_span buf, usz* off, u64* prev_type, moqkvp* out) {
  usz at = *off;
  int r  = moqkvp_take_at(buf, &at, *prev_type, out);
  if (r != QUIC_MOQKVP_OK) return r;
  *prev_type = out->type;
  *off       = at;
  return QUIC_MOQKVP_OK;
}

static int moqkvp_put_raw(wired_mspan buf, usz* at, wired_span raw) {
  if (raw.n > QUIC_MOQKVP_MAX_LEN) return 0;
  if (!moqvi_put(buf, at, raw.n)) return 0;
  return bytes_put(buf, at, raw);
}

static int moqkvp_put_value(wired_mspan buf, usz* at, const moqkvp* kv) {
  if (kv->type & 1) return moqkvp_put_raw(buf, at, kv->raw);
  return moqvi_put(buf, at, kv->num);
}

static int moqkvp_put_at(wired_mspan buf, usz* at, u64 prev, const moqkvp* kv) {
  if (kv->type < prev) return 0; /* Delta is unsigned: Types never go back */
  if (!moqvi_put(buf, at, kv->type - prev)) return 0;
  return moqkvp_put_value(buf, at, kv);
}

int moqkvp_put(wired_mspan buf, usz* off, u64* prev_type, const moqkvp* kv) {
  usz at = *off;
  if (!moqkvp_put_at(buf, &at, *prev_type, kv)) return 0;
  *prev_type = kv->type;
  *off       = at;
  return 1;
}
