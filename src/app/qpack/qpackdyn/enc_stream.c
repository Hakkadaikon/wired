#include "app/qpack/qpackdyn/enc_stream.h"

#include "app/qpack/qpack/dynget.h"
#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/instruction.h"
#include "app/qpack/qpack/integer.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpack/string.h"
#include "app/qpack/qpackdyn/cstr.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "common/bytes/varint/varint.h"

/* One whole encoder instruction: its bytes, the leading integer's length
 * and value, and which instruction the leading byte selected. */
typedef struct {
  wired_span     b;
  usz            n;
  u64            v;
  qpack_enc_kind kind;
} enc_ins;

/* RFC 9204 4.1.2: end offset of the string literal at b[off] whose length is
 * a bits-wide prefix integer, 0 while it is not whole in b yet. */
static usz qdyn_enc_str_end(wired_span b, usz off, u8 bits) {
  u64 len = 0;
  usz n   = qpack_int_decode(wired_span_of(b.p + off, b.n - off), bits, &len);
  return n && len <= b.n - off - n ? off + n + (usz)len : 0;
}

/* RFC 9204 4.3.1 / 4.3.4: the integer alone. */
static usz end_int(wired_span b, usz n) {
  (void)b;
  return n;
}

/* RFC 9204 4.3.2: name index, then the value string. */
static usz end_nameref(wired_span b, usz n) {
  return qdyn_enc_str_end(b, n, 7);
}

/* RFC 9204 4.3.3: a 5-bit-prefix name string, then the value string. */
static usz end_literal(wired_span b, usz n) {
  usz e = qdyn_enc_str_end(b, 0, 5);
  (void)n;
  return e ? qdyn_enc_str_end(b, e, 7) : 0;
}

static usz (*const enc_ends[4])(wired_span, usz) = {
    [QPACK_ENC_SET_CAPACITY]    = end_int,
    [QPACK_ENC_INSERT_NAME_REF] = end_nameref,
    [QPACK_ENC_INSERT_LITERAL]  = end_literal,
    [QPACK_ENC_DUPLICATE]       = end_int,
};

/* The scratch an inserted entry is built in before it enters the table: a
 * name it references may be evicted by that very insert (RFC 9204 3.2.2),
 * so the name is copied out first. One table's worth always holds an entry
 * that can fit. */

/* Append src to the scratch; 0 if it does not fit. */
static int qdyn_enc_keep(wired_obuf* sc, wired_span src) {
  return bytes_put(wired_mspan_of(sc->p, sc->cap), &sc->len, src);
}

/* Decode the value string at b[off] after the name already in sc, and
 * insert (name, value). */
static int qdyn_enc_insert_value(
    qpack_dyn* t, const wired_obuf* sc, wired_span b, usz off) {
  wired_obuf  v = {sc->p + sc->len, sc->cap - sc->len, 0};
  qpack_field f;
  if (!qpack_string_decode(wired_span_of(b.p + off, b.n - off), &v)) return 0;
  f = (qpack_field){wired_span_of(sc->p, sc->len), wired_span_of(v.p, v.len)};
  return qpack_dyn_insert(t, &f);
}

/* RFC 9204 4.3.1 / 5: a capacity past the advertised limit is an error. */
static int qdyn_enc_capacity(const enc_ins* i, qpack_dyn* t, u64 max) {
  if (!qpack_capacity_within_limit(i->v, max)) return 0;
  qpack_dyn_set_capacity(t, (usz)i->v);
  return 1;
}

/* RFC 9204 4.3.2: T=1 names a static entry (Appendix A). */
static int qdyn_enc_static_name(const qpack_dyn* t, u64 idx, wired_obuf* sc) {
  const char *n, *v;
  (void)t;
  if (!qpack_static_get((usz)idx, &n, &v)) return 0;
  return qdyn_enc_keep(sc, wired_span_of((const u8*)n, qdyn_cstr_len(n)));
}

/* RFC 9204 4.3.2: T=0 names a dynamic entry by encoder-relative index. */
static int qdyn_enc_dynamic_name(const qpack_dyn* t, u64 rel, wired_obuf* sc) {
  qpack_field f;
  return qpack_dyn_get_enc_rel(t, rel, &f) && qdyn_enc_keep(sc, f.name);
}

/* The T bit sits just above the 6-bit name index. */
#define QPACK_ENC_NAMEREF_T 0x40

static int (*const qdyn_enc_names[2])(const qpack_dyn*, u64, wired_obuf*) = {
    qdyn_enc_dynamic_name, qdyn_enc_static_name};

static int do_nameref(const enc_ins* i, qpack_dyn* t, u64 max) {
  u8         sb[QPACK_DYN_MAX_CAPACITY];
  wired_obuf sc        = {sb, sizeof sb, 0};
  int        is_static = (i->b.p[0] & QPACK_ENC_NAMEREF_T) != 0;
  (void)max;
  return qdyn_enc_names[is_static](t, i->v, &sc) &&
         qdyn_enc_insert_value(t, &sc, i->b, i->n);
}

/* RFC 9204 4.3.3 */
static int do_literal(const enc_ins* i, qpack_dyn* t, u64 max) {
  u8         sb[QPACK_DYN_MAX_CAPACITY];
  wired_obuf sc  = {sb, sizeof sb, 0};
  usz        off = qpack_string_decode_pfx(i->b, 5, &sc);
  (void)max;
  return off && qdyn_enc_insert_value(t, &sc, i->b, off);
}

/* Copy entry f into the scratch, then insert the copy. */
static int qdyn_enc_insert_copy(qpack_dyn* t, const qpack_field* f) {
  u8          sb[QPACK_DYN_MAX_CAPACITY];
  wired_obuf  sc = {sb, sizeof sb, 0};
  qpack_field c;
  qdyn_enc_keep(&sc, f->name);
  qdyn_enc_keep(&sc, f->value);
  c = (qpack_field){
      wired_span_of(sc.p, f->name.n),
      wired_span_of(sc.p + f->name.n, f->value.n)};
  return qpack_dyn_insert(t, &c);
}

/* RFC 9204 4.3.4 */
static int do_duplicate(const enc_ins* i, qpack_dyn* t, u64 max) {
  qpack_field f;
  (void)max;
  return qpack_dyn_get_enc_rel(t, i->v, &f) && qdyn_enc_insert_copy(t, &f);
}

static int (*const enc_applies[4])(const enc_ins*, qpack_dyn*, u64) = {
    [QPACK_ENC_SET_CAPACITY]    = qdyn_enc_capacity,
    [QPACK_ENC_INSERT_NAME_REF] = do_nameref,
    [QPACK_ENC_INSERT_LITERAL]  = do_literal,
    [QPACK_ENC_DUPLICATE]       = do_duplicate,
};

/* Frame the whole instruction at buf's head into *i; 0 while incomplete. */
static usz frame_ins(wired_span buf, enc_ins* i) {
  usz end;
  i->n = qpack_enc_instr_decode(buf, &i->kind, &i->v);
  end  = i->n ? enc_ends[i->kind](buf, i->n) : 0;
  i->b = wired_span_of(buf.p, end);
  return end;
}

usz qdyn_enc_apply(wired_span buf, qpack_dyn* t, u64 max, u16* err) {
  enc_ins i;
  usz     end = frame_ins(buf, &i);
  if (!end) return 0;
  if (!enc_applies[i.kind](&i, t, max)) {
    *err = QPACK_ENCODER_STREAM_ERROR;
    return 0;
  }
  return end;
}

/* RFC 9000 2.2: drop the part of d below base (already consumed). 0 when
 * nothing new remains. */
static int rx_trim(const qdyn_encrx* rx, u64* off, wired_span* d) {
  u64 drop = *off < rx->base ? rx->base - *off : 0;
  if (drop >= d->n) return 0;
  d->p += drop;
  d->n -= (usz)drop;
  *off += drop;
  return 1;
}

/* Bit i of the received-byte bitmap. */
static int rx_has(const qdyn_encrx* rx, usz i) {
  return (rx->have[i / 8] >> (i % 8)) & 1;
}

static void rx_mark(qdyn_encrx* rx, usz i, int v) {
  u8 m            = (u8)(1u << (i % 8));
  rx->have[i / 8] = (u8)((rx->have[i / 8] & ~m) | (v ? m : 0));
}

/* Write d at off into the window; 0 if it reaches past the window. */
static int rx_store(qdyn_encrx* rx, u64 off, wired_span d) {
  u64 at = off - rx->base;
  if (at + d.n > QDYN_ENCRX_CAP) return 0;
  bytes_memcpy(rx->buf + at, d.p, d.n);
  for (usz i = 0; i < d.n; i++) rx_mark(rx, (usz)at + i, 1);
  rx->hi = (usz)u64_max(rx->hi, at + d.n);
  return 1;
}

static int rx_land(qdyn_encrx* rx, u64 off, wired_span d) {
  return !rx_trim(rx, &off, &d) || rx_store(rx, off, d);
}

/* Bytes contiguous from base. */
static usz qdyn_encrx_ready(const qdyn_encrx* rx) {
  usz n = 0;
  while (n < rx->hi && rx_has(rx, n)) n++;
  return n;
}

/* Apply the whole instructions in the contiguous prefix; bytes consumed. */
static usz rx_apply(qdyn_encrx* rx, qpack_dyn* t, u64 max, u16* err) {
  usz ready = qdyn_encrx_ready(rx), used = 0, n;
  do {
    n = qdyn_enc_apply(
        wired_span_of(rx->buf + used, ready - used), t, max, err);
    used += n;
  } while (n);
  return used;
}

/* Mark byte i of the first `bytes`, 0 past them. */
static u8 rx_have_byte(const qdyn_encrx* rx, usz i, usz bytes) {
  return i < bytes ? rx->have[i] : 0;
}

/* Shift the received-byte marks down by n a whole mark byte at a time,
 * clearing the vacated top (marks past hi are always clear). */
static void rx_shift_marks(qdyn_encrx* rx, usz n) {
  usz bytes = (rx->hi + 7) / 8, q = n / 8, r = n % 8;
  for (usz i = 0; i < bytes; i++)
    rx->have[i] = (u8)((rx_have_byte(rx, i + q, bytes) >> r) |
                       (rx_have_byte(rx, i + q + 1, bytes) << (8 - r)));
}

/* Slide the consumed prefix (n <= the contiguous bytes) out of the window:
 * the bytes and their marks move down by n, base up by n. */
static void rx_slide(qdyn_encrx* rx, usz n) {
  if (n == 0) return; /* nothing consumed: moving the window is pure cost */
  bytes_move_down(rx->buf, rx->buf + n, rx->hi - n);
  rx_shift_marks(rx, n);
  rx->hi -= n;
  rx->base += n;
}

void qdyn_encrx_take(qdyn_encrx* rx, u64 stream_id) {
  bytes_memset(rx->have, 0, (rx->hi + 7) / 8);
  rx->base      = 0;
  rx->hi        = 0;
  rx->type_len  = 0;
  rx->stream_id = stream_id;
}

/* RFC 9204 4.2: the encoder stream's type. */
#define QDYN_ENC_STREAM_TYPE 0x02

/* RFC 9204 4.2 / RFC 9000 16: once the held stream's leading type varint is
 * whole, claim the stream (consuming the varint) if it is the encoder type,
 * else let it go -- its bytes belong to some other stream type. */
static void qdyn_encrx_identify(qdyn_encrx* rx) {
  u64 v;
  usz n = 0;
  if (!varint_take(wired_span_of(rx->buf, qdyn_encrx_ready(rx)), &n, &v))
    return;
  if (v != QDYN_ENC_STREAM_TYPE) {
    qdyn_encrx_take(rx, 0);
    return;
  }
  rx->type_len = n;
  rx_slide(rx, n);
}

/* Identify the held stream if still needed, then apply what a claimed one
 * has contiguous. */
static void qdyn_encrx_settle(qdyn_encrx* rx, qpack_dyn* t, u64 max, u16* err) {
  if (!rx->type_len) qdyn_encrx_identify(rx);
  if (rx->type_len) rx_slide(rx, rx_apply(rx, t, max, err));
}

/* d reached past the window: an error only on the claimed encoder stream
 * (a flow-control violation); an unidentified stream's bytes are not ours
 * to judge. */
static u16 qdyn_encrx_overflow(const qdyn_encrx* rx) {
  return rx->type_len ? QPACK_ENCODER_STREAM_ERROR : 0;
}

int qdyn_encrx_feed(
    qdyn_encrx* rx, u64 off, wired_span d, qpack_dyn* t, u64 max, u16* err) {
  u16 e = 0;
  if (!rx_land(rx, off, d))
    e = qdyn_encrx_overflow(rx);
  else
    qdyn_encrx_settle(rx, t, max, &e);
  if (e) *err = e;
  return e == 0;
}

u64 qdyn_encrx_credit(const qdyn_encrx* rx) {
  return rx->base + QDYN_ENCRX_CAP;
}
