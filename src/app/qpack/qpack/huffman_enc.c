#include "app/qpack/qpack/huffman_impl.h"

/* The canonical rank of symbol s: its position in qpack_hsym. */
static u32 sym_rank(u32 s) {
  u32 i = 0;
  while (qpack_hsym[i] != s) {
    i++;
  }
  return i;
}

/* The code length of canonical rank i: the L whose run of qpack_hcnt[L] ranks
 * starting at qpack_hidx[L] holds it (5 is the shortest code). */
static u32 rank_len(u32 i) {
  u32 L = 5;
  while (i >= (u32)qpack_hidx[L] + qpack_hcnt[L]) {
    L++;
  }
  return L;
}

static u32 huff_code(u32 s, u32* len) {
  u32 i = sym_rank(s);
  *len  = rank_len(i);
  return qpack_hfirst[*len] + (i - qpack_hidx[*len]);
}

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
  u32 L, pad;
  for (usz i = 0; i < src.n; i++) {
    u32 code = huff_code(src.p[i], &L);
    put_code(&w, code, L);
  }
  pad = (8 - w.nbits) & 7; /* RFC 7541 5.2: EOS-prefix (all ones) padding */
  put_code(&w, (1u << pad) - 1u, pad);
  return w.len;
}
