#include "app/qpack/qpack/instruction.h"

#include "app/qpack/qpack/integer.h"

/* Each instruction: the fixed high-bit pattern, the mask covering those bits,
 * and the prefix length of the trailing integer (RFC 9204 4.3 / 4.4). The
 * pattern occupies the bits above the prefix; mask selects them for matching.
 */
typedef struct {
  u8 pattern;
  u8 mask;
  u8 prefix_bits;
} instr_spec;

static const instr_spec enc_specs[] = {
    [QPACK_ENC_SET_CAPACITY] = {0x20, 0xe0, 5}, /* 001 */
    [QPACK_ENC_INSERT_NAME_REF] =
        {0x80, 0x80, 6},                          /* 1   (T bit is in prefix) */
    [QPACK_ENC_INSERT_LITERAL] = {0x40, 0xc0, 5}, /* 01  (H bit is in prefix) */
    [QPACK_ENC_DUPLICATE]      = {0x00, 0xe0, 5}, /* 000 */
};

static const instr_spec dec_specs[] = {
    [QPACK_DEC_SECTION_ACK]   = {0x80, 0x80, 7}, /* 1  */
    [QPACK_DEC_STREAM_CANCEL] = {0x40, 0xc0, 6}, /* 01 */
    [QPACK_DEC_INSERT_COUNT]  = {0x00, 0xc0, 6}, /* 00 */
};

/* Encode value under the given spec: its pattern in the high bits, value in an
 * N-bit prefix integer. Returns bytes written or 0. */
static usz instr_encode(wired_mspan buf, const instr_spec* s, u64 value) {
  qpack_pfx pfx = {s->prefix_bits, s->pattern};
  return qpack_int_encode(buf, pfx, value);
}

/* The byte's high bits select this spec. */
static int spec_matches(const instr_spec* s, u8 b) {
  return (b & s->mask) == s->pattern;
}

/* Find the spec in specs[0..count) whose pattern the leading byte matches.
 * Returns its index, or count if none (cannot happen for total maskings). */
static usz spec_classify(const instr_spec* specs, usz count, u8 b) {
  usz i = 0;
  while (i < count && !spec_matches(&specs[i], b)) i++;
  return i;
}

/* A spec table: the instruction set of one unidirectional stream. */
typedef struct {
  const instr_spec* specs;
  usz               count;
} instr_set;

/* One decoded instruction: which spec matched and its integer field. */
typedef struct {
  usz kind;
  u64 value;
} instr_field;

/* Decode one instruction from the set: classify the leading byte, read its
 * prefix integer. Fills *f, returns bytes consumed or 0. */
static usz instr_decode(wired_span buf, const instr_set* s, instr_field* f) {
  if (buf.n == 0) return 0;
  f->kind = spec_classify(s->specs, s->count, buf.p[0]);
  if (f->kind >= s->count) return 0;
  return qpack_int_decode(buf, s->specs[f->kind].prefix_bits, &f->value);
}

usz qpack_enc_instr_encode(wired_mspan buf, qpack_enc_kind kind, u64 value) {
  return instr_encode(buf, &enc_specs[kind], value);
}

usz qpack_enc_instr_decode(wired_span buf, qpack_enc_kind* kind, u64* value) {
  instr_set   s = {enc_specs, 4};
  instr_field f;
  usz         r = instr_decode(buf, &s, &f);
  if (r) {
    *kind  = (qpack_enc_kind)f.kind;
    *value = f.value;
  }
  return r;
}

usz qpack_dec_instr_encode(wired_mspan buf, qpack_dec_kind kind, u64 value) {
  return instr_encode(buf, &dec_specs[kind], value);
}

usz qpack_dec_instr_decode(wired_span buf, qpack_dec_kind* kind, u64* value) {
  instr_set   s = {dec_specs, 3};
  instr_field f;
  usz         r = instr_decode(buf, &s, &f);
  if (r) {
    *kind  = (qpack_dec_kind)f.kind;
    *value = f.value;
  }
  return r;
}
