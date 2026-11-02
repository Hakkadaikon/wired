#include "app/qpack/qpack/huffman_impl.h"

/* RFC 7541 Appendix B, per octet: its code length L (low 5 bits) and its
 * offset k in the canonical run of length-L codes (k << 5), listed from the
 * tables in huffman.c; the code is qpack_hfirst[L] + k. */
static const u16 huff_lk[256] = {
    13,  23,  28,  60,  92,  124, 156, 188, 220, 24,  30,  252, 284, 62,  316,
    348, 380, 412, 444, 476, 508, 540, 94,  572, 604, 636, 668, 700, 732, 764,
    796, 828, 6,   10,  42,  12,  45,  38,  8,   11,  74,  106, 40,  43,  72,
    70,  102, 134, 5,   37,  69,  166, 198, 230, 262, 294, 326, 358, 7,   104,
    15,  390, 44,  138, 77,  422, 39,  71,  103, 135, 167, 199, 231, 263, 295,
    327, 359, 391, 423, 455, 487, 519, 551, 583, 615, 647, 679, 711, 136, 743,
    168, 109, 19,  141, 14,  454, 47,  101, 486, 133, 518, 165, 550, 582, 614,
    197, 775, 807, 646, 678, 710, 229, 742, 839, 774, 261, 293, 806, 871, 903,
    935, 967, 999, 79,  75,  46,  173, 860, 20,  22,  52,  84,  54,  86,  118,
    55,  150, 87,  119, 151, 183, 215, 56,  247, 88,  120, 182, 279, 152, 311,
    343, 375, 407, 21,  214, 439, 246, 471, 503, 184, 278, 53,  116, 310, 342,
    535, 567, 85,  599, 374, 406, 216, 117, 438, 631, 663, 149, 181, 470, 213,
    695, 502, 727, 759, 148, 534, 566, 598, 791, 630, 662, 823, 26,  58,  180,
    51,  694, 855, 726, 25,  90,  122, 154, 27,  59,  186, 248, 57,  83,  245,
    218, 91,  123, 250, 155, 280, 277, 309, 282, 314, 892, 187, 219, 251, 212,
    312, 244, 341, 758, 373, 405, 887, 790, 822, 89,  121, 344, 376, 346, 919,
    378, 283, 410, 442, 315, 347, 379, 411, 443, 924, 475, 507, 539, 571, 603,
    474,
};

/* Encoder bit writer: acc holds nbits pending bits (at most 7 + 30). Octets
 * past cap are counted in len but not stored. */
typedef struct {
  u64 acc;
  u32 nbits;
  u8* out;
  usz cap;
  usz len;
} hwr;

static void put_octet(hwr* w, u8 b) {
  if (w->len < w->cap) {
    w->out[w->len] = b;
  }
  w->len++;
}

/* Append the L-bit code, flushing every whole octet. */
static void put_code(hwr* w, u32 code, u32 L) {
  w->acc = (w->acc << L) | code;
  w->nbits += L;
  while (w->nbits >= 8) {
    w->nbits -= 8;
    put_octet(w, (u8)(w->acc >> w->nbits));
  }
}

usz qpack_huffman_encode(wired_span src, wired_mspan dst) {
  hwr w = {0, 0, dst.p, dst.n, 0};
  u32 pad;
  for (usz i = 0; i < src.n; i++) {
    u32 lk = huff_lk[src.p[i]];
    put_code(&w, qpack_hfirst[lk & 31] + (lk >> 5), lk & 31);
  }
  pad = (8 - w.nbits) & 7; /* RFC 7541 5.2: EOS-prefix (all ones) padding */
  put_code(&w, (1u << pad) - 1u, pad);
  return w.len;
}
