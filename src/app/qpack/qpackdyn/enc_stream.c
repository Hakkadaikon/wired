#include "app/qpack/qpackdyn/enc_stream_impl.h"

static usz qdyn_enc_str_end(wired_span b, usz off, u8 bits);
static usz end_int(wired_span b, usz n);
static usz end_nameref(wired_span b, usz n);
static usz end_literal(wired_span b, usz n);
static int qdyn_enc_static_name(const qpack_dyn* t, u64 idx, wired_obuf* sc);
static int qdyn_enc_dynamic_name(const qpack_dyn* t, u64 rel, wired_obuf* sc);

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

usz (*const enc_ends[4])(wired_span, usz) = {
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
int qdyn_enc_keep(wired_obuf* sc, wired_span src) {
  return bytes_put(wired_mspan_of(sc->p, sc->cap), &sc->len, src);
}

/* Decode the value string at b[off] after the name already in sc, and
 * insert (name, value). */
int qdyn_enc_insert_value(
    qpack_dyn* t, const wired_obuf* sc, wired_span b, usz off) {
  wired_obuf  v = {sc->p + sc->len, sc->cap - sc->len, 0};
  qpack_field f;
  if (!qpack_string_decode(wired_span_of(b.p + off, b.n - off), &v)) {
    return 0;
  }
  f = (qpack_field){wired_span_of(sc->p, sc->len), wired_span_of(v.p, v.len)};
  return qpack_dyn_insert(t, &f);
}

/* RFC 9204 4.3.1 / 5: a capacity past the advertised limit is an error. */
int qdyn_enc_capacity(const enc_ins* i, qpack_dyn* t, u64 max) {
  if (!qpack_capacity_within_limit(i->v, max)) {
    return 0;
  }
  qpack_dyn_set_capacity(t, (usz)i->v);
  return 1;
}

/* RFC 9204 4.3.2: T=1 names a static entry (Appendix A). */
static int qdyn_enc_static_name(const qpack_dyn* t, u64 idx, wired_obuf* sc) {
  const char *n, *v;
  (void)t;
  if (!qpack_static_get((usz)idx, &n, &v)) {
    return 0;
  }
  return qdyn_enc_keep(sc, wired_span_of((const u8*)n, qdyn_cstr_len(n)));
}

/* RFC 9204 4.3.2: T=0 names a dynamic entry by encoder-relative index. */
static int qdyn_enc_dynamic_name(const qpack_dyn* t, u64 rel, wired_obuf* sc) {
  qpack_field f;
  return qpack_dyn_get_enc_rel(t, rel, &f) && qdyn_enc_keep(sc, f.name);
}

static int (*const qdyn_enc_names[2])(const qpack_dyn*, u64, wired_obuf*) = {
    qdyn_enc_dynamic_name, qdyn_enc_static_name};

int qdyn_do_nameref(const enc_ins* i, qpack_dyn* t, u64 max) {
  u8         sb[QPACK_DYN_MAX_CAPACITY];
  wired_obuf sc        = {sb, sizeof sb, 0};
  int        is_static = (i->b.p[0] & QPACK_ENC_NAMEREF_T) != 0;
  (void)max;
  return qdyn_enc_names[is_static](t, i->v, &sc) &&
         qdyn_enc_insert_value(t, &sc, i->b, i->n);
}
