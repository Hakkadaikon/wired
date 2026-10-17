#include "app/qpack/qpack/huffman_impl.h"

static void step_octet(hctx* c, u8 byte);
static void feed(hctx* c, wired_span src);
static int  pad_valid(const hctx* c);
static int  decode_ok(const hctx* c);

/* Feed the 8 bits of one octet, most significant first, halting on error. */
static void step_octet(hctx* c, u8 byte) {
  for (u32 b = 8; b != 0 && c->ok; b--)
    qpack_step_bit(c, (byte >> (b - 1)) & 1u);
}

/* Feed every input octet into c; a broken octet leaves c->ok clear so the
 * remaining octets are stepped over as no-ops. */
static void feed(hctx* c, wired_span src) {
  for (usz i = 0; i < src.n; i++) step_octet(c, src.p[i]);
}

/* RFC 7541 5.2: the leftover bits must form valid padding -- fewer than 8 and
 * all ones (the EOS prefix). c->ok must also still hold. */
static int pad_valid(const hctx* c) {
  return c->nbits < 8 && (c->nbits == 0 || c->acc == ((1u << c->nbits) - 1u));
}

/* The decode succeeded if no rule was broken and the trailing bits pad cleanly.
 */
static int decode_ok(const hctx* c) { return c->ok && pad_valid(c); }

int qpack_huffman_decode(wired_span src, wired_obuf* dst) {
  hctx c = {0, 0, dst->p, dst->cap, 0, 1};
  feed(&c, src);
  if (!decode_ok(&c)) return 0;
  dst->len = c.olen;
  return 1;
}
