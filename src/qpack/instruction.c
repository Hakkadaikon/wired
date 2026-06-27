#include "qpack/instruction.h"
#include "qpack/integer.h"

/* Each instruction: the fixed high-bit pattern, the mask covering those bits,
 * and the prefix length of the trailing integer (RFC 9204 4.3 / 4.4). The
 * pattern occupies the bits above the prefix; mask selects them for matching. */
typedef struct {
    u8 pattern;
    u8 mask;
    u8 prefix_bits;
} instr_spec;

static const instr_spec enc_specs[] = {
    [QUIC_QPACK_ENC_SET_CAPACITY]    = {0x20, 0xe0, 5}, /* 001 */
    [QUIC_QPACK_ENC_INSERT_NAME_REF] = {0x80, 0x80, 6}, /* 1   (T bit is in prefix) */
    [QUIC_QPACK_ENC_INSERT_LITERAL]  = {0x40, 0xc0, 5}, /* 01  (H bit is in prefix) */
    [QUIC_QPACK_ENC_DUPLICATE]       = {0x00, 0xe0, 5}, /* 000 */
};

static const instr_spec dec_specs[] = {
    [QUIC_QPACK_DEC_SECTION_ACK]   = {0x80, 0x80, 7}, /* 1  */
    [QUIC_QPACK_DEC_STREAM_CANCEL] = {0x40, 0xc0, 6}, /* 01 */
    [QUIC_QPACK_DEC_INSERT_COUNT]  = {0x00, 0xc0, 6}, /* 00 */
};

/* Encode value under the given spec: its pattern in the high bits, value in an
 * N-bit prefix integer. Returns bytes written or 0. */
static usz instr_encode(u8 *buf, usz cap, const instr_spec *s, u64 value)
{
    return quic_qpack_int_encode(buf, cap, s->prefix_bits, s->pattern, value);
}

/* The byte's high bits select this spec. */
static int spec_matches(const instr_spec *s, u8 b) { return (b & s->mask) == s->pattern; }

/* Find the spec in specs[0..count) whose pattern the leading byte matches.
 * Returns its index, or count if none (cannot happen for total maskings). */
static usz spec_classify(const instr_spec *specs, usz count, u8 b)
{
    usz i = 0;
    while (i < count && !spec_matches(&specs[i], b)) i++;
    return i;
}

/* Decode one instruction from specs[0..count): classify the leading byte, read
 * its prefix integer. Sets *kind and *value, returns bytes consumed or 0. */
static usz instr_decode(const u8 *buf, usz n, const instr_spec *specs, usz count,
                        usz *kind, u64 *value)
{
    if (n == 0) return 0;
    *kind = spec_classify(specs, count, buf[0]);
    if (*kind >= count) return 0;
    return quic_qpack_int_decode(buf, n, specs[*kind].prefix_bits, value);
}

usz quic_qpack_enc_instr_encode(u8 *buf, usz cap, quic_qpack_enc_kind kind, u64 value)
{
    return instr_encode(buf, cap, &enc_specs[kind], value);
}

usz quic_qpack_enc_instr_decode(const u8 *buf, usz n, quic_qpack_enc_kind *kind, u64 *value)
{
    usz k;
    usz r = instr_decode(buf, n, enc_specs, 4, &k, value);
    if (r) *kind = (quic_qpack_enc_kind)k;
    return r;
}

usz quic_qpack_dec_instr_encode(u8 *buf, usz cap, quic_qpack_dec_kind kind, u64 value)
{
    return instr_encode(buf, cap, &dec_specs[kind], value);
}

usz quic_qpack_dec_instr_decode(const u8 *buf, usz n, quic_qpack_dec_kind *kind, u64 *value)
{
    usz k;
    usz r = instr_decode(buf, n, dec_specs, 3, &k, value);
    if (r) *kind = (quic_qpack_dec_kind)k;
    return r;
}
