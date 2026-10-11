#include "app/qpack/qpackdyn/enc_stream.h"

#include "app/qpack/qpack/dynget.h"
#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/instruction.h"
#include "app/qpack/qpack/integer.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpack/string.h"
#include "app/qpack/qpackdyn/cstr.h"
#include "common/bytes/util/bytes.h"

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
static usz str_end(wired_span b, usz off, u8 bits) {
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
static usz end_nameref(wired_span b, usz n) { return str_end(b, n, 7); }

/* RFC 9204 4.3.3: a 5-bit-prefix name string, then the value string. */
static usz end_literal(wired_span b, usz n) {
  usz e = str_end(b, 0, 5);
  (void)n;
  return e ? str_end(b, e, 7) : 0;
}

static usz (*const enc_ends[4])(wired_span, usz) = {
    [QPACK_ENC_SET_CAPACITY]    = end_int,
    [QPACK_ENC_INSERT_NAME_REF] = end_nameref,
    [QPACK_ENC_INSERT_LITERAL]  = end_literal,
    [QPACK_ENC_DUPLICATE]       = end_int,
};

/* Decode the value string at off and insert (name, value). */
static int insert_value(qpack_dyn* t, wired_span name, wired_span b, usz off) {
  u8          vb[QPACK_DYN_MAX_VALUE];
  wired_obuf  v = {vb, sizeof vb, 0};
  qpack_field f;
  if (!qpack_string_decode(wired_span_of(b.p + off, b.n - off), &v)) return 0;
  f = (qpack_field){name, wired_span_of(vb, v.len)};
  return qpack_dyn_insert(t, &f);
}

/* RFC 9204 4.3.1 / 5: a capacity past the advertised limit is an error. */
static int do_capacity(const enc_ins* i, qpack_dyn* t, u64 max) {
  if (!qpack_capacity_within_limit(i->v, max)) return 0;
  qpack_dyn_set_capacity(t, (usz)i->v);
  return 1;
}

/* RFC 9204 4.3.2: T=1 names a static entry (Appendix A). */
static int static_name(u64 idx, wired_span* name) {
  const char *n, *v;
  if (!qpack_static_get((usz)idx, &n, &v)) return 0;
  *name = wired_span_of((const u8*)n, qdyn_cstr_len(n));
  return 1;
}

/* RFC 9204 4.3.2: T=0 names a dynamic entry by encoder-relative index. */
static int dynamic_name(const qpack_dyn* t, u64 rel, wired_span* name) {
  qpack_field f;
  if (!qpack_dyn_get_enc_rel(t, rel, &f)) return 0;
  *name = f.name;
  return 1;
}

/* The T bit sits just above the 6-bit name index. */
#define QPACK_ENC_NAMEREF_T 0x40

static int do_nameref(const enc_ins* i, qpack_dyn* t, u64 max) {
  wired_span name;
  int ok = (i->b.p[0] & QPACK_ENC_NAMEREF_T) ? static_name(i->v, &name)
                                             : dynamic_name(t, i->v, &name);
  (void)max;
  return ok && insert_value(t, name, i->b, i->n);
}

/* RFC 9204 4.3.3 */
static int do_literal(const enc_ins* i, qpack_dyn* t, u64 max) {
  u8         nb[QPACK_DYN_MAX_NAME];
  wired_obuf name = {nb, sizeof nb, 0};
  usz        off  = qpack_string_decode_pfx(i->b, 5, &name);
  (void)max;
  return off && insert_value(t, wired_span_of(nb, name.len), i->b, off);
}

/* RFC 9204 4.3.4 */
static int do_duplicate(const enc_ins* i, qpack_dyn* t, u64 max) {
  qpack_field f;
  (void)max;
  return qpack_dyn_get_enc_rel(t, i->v, &f) && qpack_dyn_insert(t, &f);
}

static int (*const enc_applies[4])(const enc_ins*, qpack_dyn*, u64) = {
    [QPACK_ENC_SET_CAPACITY]    = do_capacity,
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

/* RFC 9000 2.2: drop the part of d below base (already applied). 0 when
 * nothing new remains. */
static int rx_trim(const qdyn_encrx* rx, u64* off, wired_span* d) {
  u64 drop = *off < rx->base ? rx->base - *off : 0;
  if (drop >= d->n) return 0;
  d->p += drop;
  d->n -= (usz)drop;
  *off += drop;
  return 1;
}

/* Write d at off into the window; 0 if it reaches past the window. */
static int rx_store(qdyn_encrx* rx, u64 off, wired_span d) {
  u64 at = off - rx->base;
  if (at + d.n > QDYN_ENCRX_CAP) return 0;
  bytes_memcpy(rx->buf + at, d.p, d.n);
  bytes_memset(rx->have + at, 1, d.n);
  return 1;
}

static int rx_land(qdyn_encrx* rx, u64 off, wired_span d) {
  return !rx_trim(rx, &off, &d) || rx_store(rx, off, d);
}

/* Bytes contiguous from base. */
static usz rx_ready(const qdyn_encrx* rx) {
  usz n = 0;
  while (n < QDYN_ENCRX_CAP && rx->have[n]) n++;
  return n;
}

/* Apply the whole instructions in the contiguous prefix; bytes consumed. */
static usz rx_apply(qdyn_encrx* rx, qpack_dyn* t, u64 max, u16* err) {
  usz ready = rx_ready(rx), used = 0, n;
  do {
    n = qdyn_enc_apply(
        wired_span_of(rx->buf + used, ready - used), t, max, err);
    used += n;
  } while (n);
  return used;
}

/* Slide the applied prefix out of the window. */
static void rx_slide(qdyn_encrx* rx, usz n) {
  bytes_move_down(rx->buf, rx->buf + n, QDYN_ENCRX_CAP - n);
  bytes_move_down(rx->have, rx->have + n, QDYN_ENCRX_CAP - n);
  bytes_memset(rx->have + QDYN_ENCRX_CAP - n, 0, n);
  rx->base += n;
}

int qdyn_encrx_feed(
    qdyn_encrx* rx, u64 off, wired_span d, qpack_dyn* t, u64 max, u16* err) {
  u16 e = 0;
  if (!rx_land(rx, off, d))
    e = QPACK_ENCODER_STREAM_ERROR;
  else
    rx_slide(rx, rx_apply(rx, t, max, &e));
  if (e) *err = e;
  return e == 0;
}
