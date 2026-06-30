#include "app/qpack/qpack/huffman.h"

/* RFC 7541 Appendix B static Huffman code, in canonical form. HSYM lists the
 * 257 symbols (0..255 plus EOS=256) ordered by (code length, code value).
 * For a code of length L: HFIRST[L] is the first canonical code of that
 * length, HIDX[L] the index of its first symbol in HSYM, HCNT[L] the number
 * of codes of that length. A code value c of length L decodes to
 * HSYM[HIDX[L] + (c - HFIRST[L])] when c - HFIRST[L] < HCNT[L]. */
#define HUFF_MAXLEN 30

static const u16 HSYM[257] = {
    48,  49,  50,  97,  99,  101, 105, 111, 115, 116, 32,  37,  45,  46,  47,
    51,  52,  53,  54,  55,  56,  57,  61,  65,  95,  98,  100, 102, 103, 104,
    108, 109, 110, 112, 114, 117, 58,  66,  67,  68,  69,  70,  71,  72,  73,
    74,  75,  76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  89,
    106, 107, 113, 118, 119, 120, 121, 122, 38,  42,  44,  59,  88,  90,  33,
    34,  40,  41,  63,  39,  43,  124, 35,  62,  0,   36,  64,  91,  93,  126,
    94,  125, 60,  96,  123, 92,  195, 208, 128, 130, 131, 162, 184, 194, 224,
    226, 153, 161, 167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129,
    132, 133, 134, 136, 146, 154, 156, 160, 163, 164, 169, 170, 173, 178, 181,
    185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1,   135, 137, 138, 139,
    140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174,
    175, 180, 182, 183, 188, 191, 197, 231, 239, 9,   142, 144, 145, 148, 159,
    171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202,
    205, 210, 213, 218, 219, 238, 240, 242, 243, 255, 203, 204, 211, 212, 214,
    221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252, 253, 254, 2,
    3,   4,   5,   6,   7,   8,   11,  12,  14,  15,  16,  17,  18,  19,  20,
    21,  23,  24,  25,  26,  27,  28,  29,  30,  31,  127, 220, 249, 10,  13,
    22,  256,
};
static const u32 HFIRST[31] = {
    0,         0,         0,         0,        0,        0,        20,
    92,        248,       508,       1016,     2042,     4090,     8184,
    16380,     32764,     65534,     131068,   262136,   524272,   1048550,
    2097116,   4194258,   8388568,   16777194, 33554412, 67108832, 134217694,
    268435426, 536870910, 1073741820};
static const u16 HIDX[31] = {
    0,  0,  0,  0,  0,  0,   10,  36,  68,  74,  74,  79,  82,  84,  90, 92,
    95, 95, 95, 95, 98, 106, 119, 145, 174, 186, 190, 205, 224, 253, 253};
static const u16 HCNT[31] = {0,  0,  0,  0, 0,  10, 26, 32, 6, 0, 5,
                             3,  2,  6,  2, 3,  0,  0,  0,  3, 8, 13,
                             26, 29, 12, 4, 15, 19, 29, 0,  4};

/* Running decode state: a bit accumulator (acc) of nbits bits, plus the
 * output cursor (out, capacity dcap). ok stays 1 until a rule is broken. */
typedef struct {
  u32 acc;
  u32 nbits;
  u8 *out;
  usz dcap;
  usz olen;
  int ok;
} hctx;

/* A complete code of length L sits in acc when its offset is within range. */
static int code_ready(u32 acc, u32 L) {
  return HCNT[L] != 0 && (acc - HFIRST[L]) < HCNT[L];
}

/* Write one decoded symbol; fail on EOS (sym > 255) or dst overflow. */
static void put_sym(hctx *c, u16 sym) {
  if (sym > 255 || c->olen >= c->dcap) {
    c->ok = 0;
    return;
  }
  c->out[c->olen++] = (u8)sym;
}

/* A code completed at length nbits: emit its symbol and reset the bit run. */
static void emit_code(hctx *c) {
  put_sym(c, HSYM[HIDX[c->nbits] + (c->acc - HFIRST[c->nbits])]);
  c->acc   = 0;
  c->nbits = 0;
}

/* Fold one input bit into the accumulator, completing a symbol if ready or
 * failing once the run exceeds the longest code (RFC 7541 Appendix B). */
static void step_bit(hctx *c, u32 bit) {
  c->acc = (c->acc << 1) | bit;
  c->nbits++;
  if (c->nbits > HUFF_MAXLEN) {
    c->ok = 0;
    return;
  }
  if (code_ready(c->acc, c->nbits)) emit_code(c);
}

/* Feed the 8 bits of one octet, most significant first, halting on error. */
static void step_octet(hctx *c, u8 byte) {
  for (u32 b = 8; b != 0 && c->ok; b--) step_bit(c, (byte >> (b - 1)) & 1u);
}

/* Feed every input octet into c; a broken octet leaves c->ok clear so the
 * remaining octets are stepped over as no-ops. */
static void feed(hctx *c, const u8 *src, usz src_len) {
  for (usz i = 0; i < src_len; i++) step_octet(c, src[i]);
}

/* RFC 7541 5.2: the leftover bits must form valid padding -- fewer than 8 and
 * all ones (the EOS prefix). c->ok must also still hold. */
static int pad_valid(const hctx *c) {
  return c->nbits < 8 && (c->nbits == 0 || c->acc == ((1u << c->nbits) - 1u));
}

/* The decode succeeded if no rule was broken and the trailing bits pad cleanly.
 */
static int decode_ok(const hctx *c) { return c->ok && pad_valid(c); }

int quic_qpack_huffman_decode(
    const u8 *src, usz src_len, u8 *dst, usz dcap, usz *out_len) {
  hctx c = {0, 0, dst, dcap, 0, 1};
  feed(&c, src, src_len);
  if (!decode_ok(&c)) return 0;
  *out_len = c.olen;
  return 1;
}
