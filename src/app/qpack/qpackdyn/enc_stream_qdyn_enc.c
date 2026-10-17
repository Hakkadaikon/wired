#include "app/qpack/qpackdyn/enc_stream_impl.h"

static int do_literal(const enc_ins* i, qpack_dyn* t, u64 max);
static int qdyn_enc_insert_copy(qpack_dyn* t, const qpack_field* f);
static int do_duplicate(const enc_ins* i, qpack_dyn* t, u64 max);
static usz frame_ins(wired_span buf, enc_ins* i);

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
    [QPACK_ENC_INSERT_NAME_REF] = qdyn_do_nameref,
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
  if (!end) {
    return 0;
  }
  if (!enc_applies[i.kind](&i, t, max)) {
    *err = QPACK_ENCODER_STREAM_ERROR;
    return 0;
  }
  return end;
}
