#include "crypto/pki/encoding/pem/pem_impl.h"

static u8  pem_ct_range_mask(u8 c, u8 lo, u8 hi);
static int pem_match_at(wired_span text, usz i, wired_span nd);

/* RFC 7468 2: block markers. u8 arrays so spans view them directly. */
static const u8 pem_begin_tag[] = "-----BEGIN ";

const u8 pem_end_tag[] = "-----END ";

static const u8 pem_dashes[] = "-----";

static const pem_b64_range pem_b64_ranges[] = {
    {'A', 'Z', 0},  {'a', 'z', 26}, {'0', '9', 52},   {'+', '+', 62},
    {'/', '/', 63}, {'=', '=', 64}, {'\r', '\r', 65}, {'\n', '\n', 65},
};

/* 0xff if lo <= c <= hi, else 0x00, with no data-dependent branch: both
 * differences are non-negative exactly when c is inside the range, so the
 * sign bit of their OR is clear iff in range. */
static u8 pem_ct_range_mask(u8 c, u8 lo, u8 hi) {
  u32 neg = ((u32)((int)c - (int)lo) | (u32)((int)hi - (int)c)) >> 31;
  return (u8)(neg - 1);
}

/* Classify one input byte (see pem_b64_ranges); every range is always
 * evaluated so the work does not depend on which one matches. */
u8 pem_b64_code(u8 c) {
  u8 hit = 0, code = 0;
  for (usz i = 0; i < PEM_B64_RANGE_COUNT; i++) {
    const pem_b64_range* r = &pem_b64_ranges[i];
    u8                   m = pem_ct_range_mask(c, r->lo, r->hi);
    hit |= m;
    code |= (u8)(m & (u8)(c - r->lo + r->base));
  }
  return (u8)((hit & code) | ((u8)~hit & PEM_B64_INVALID));
}

/* Output byte count of a final quad by pad shape:
 * index = (q[2] is pad)*2 + (q[3] is pad); a pad in q[2] alone is invalid. */
const u8 pem_quad_n[4] = {3, 2, 0, 1};

static int pem_match_at(wired_span text, usz i, wired_span nd) {
  usz k = 0;
  while (k < nd.n && text.p[i + k] == nd.p[k]) {
    k++;
  }
  return k == nd.n;
}

/* Find needle nd in text at or after from; 1 and *pos set on a hit. */
int pem_find(wired_span text, usz from, wired_span nd, usz* pos) {
  for (usz i = from; i + nd.n <= text.n; i++) {
    if (pem_match_at(text, i, nd)) {
      *pos = i;
      return 1;
    }
  }
  return 0;
}

/* Index just past the newline ending the line that starts at or after i. */
usz pem_line_end(wired_span text, usz i) {
  while (i < text.n && text.p[i] != '\n') {
    i++;
  }
  return i + (usz)(i < text.n);
}

/* Locate "-----BEGIN <label>-----" at or after at; *body = index just past
 * the closing dashes (the rest of the line is CR/LF the decoder skips). */
int pem_head(wired_span text, usz at, wired_span* label, usz* body) {
  usz b, l;
  if (!pem_find(text, at, wired_span_of(pem_begin_tag, 11), &b)) {
    return 0;
  }
  b += 11;
  if (!pem_find(text, b, wired_span_of(pem_dashes, 5), &l)) {
    return 0;
  }
  *label = wired_span_of(text.p + b, l - b);
  *body  = l + 5;
  return 1;
}
