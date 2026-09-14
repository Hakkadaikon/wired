#include "crypto/pki/encoding/pem/pem.h"

/* RFC 7468 2: block markers. u8 arrays so spans view them directly. */
static const u8 pem_begin_tag[] = "-----BEGIN ";
static const u8 pem_end_tag[]   = "-----END ";
static const u8 pem_dashes[]    = "-----";

/* RFC 4648 4 reverse alphabet, evaluated arithmetically: 0-63 = sextet
 * value, 64 = pad '=', 65 = skip (CR/LF), 66 = invalid. A 256-entry lookup
 * table indexed by the input byte would make the cache line touched depend
 * on the decoded sextet, which for a PRIVATE KEY block (certreload decodes
 * the server's key through this path) leaks key bits to a co-resident
 * observer (CVE-2021-24116 class). Each input byte is instead run through
 * every range below, in a fixed order, with a branch-free in-range mask. */
typedef struct {
  u8 lo, hi, base;
} pem_b64_range;

static const pem_b64_range pem_b64_ranges[] = {
    {'A', 'Z', 0},  {'a', 'z', 26}, {'0', '9', 52},   {'+', '+', 62},
    {'/', '/', 63}, {'=', '=', 64}, {'\r', '\r', 65}, {'\n', '\n', 65},
};
#define PEM_B64_RANGE_COUNT (sizeof(pem_b64_ranges) / sizeof(pem_b64_ranges[0]))
#define PEM_B64_INVALID 66

/* 0xff if lo <= c <= hi, else 0x00, with no data-dependent branch: both
 * differences are non-negative exactly when c is inside the range, so the
 * sign bit of their OR is clear iff in range. */
static u8 pem_ct_range_mask(u8 c, u8 lo, u8 hi) {
  u32 neg = ((u32)((int)c - (int)lo) | (u32)((int)hi - (int)c)) >> 31;
  return (u8)(neg - 1);
}

/* Classify one input byte (see pem_b64_ranges); every range is always
 * evaluated so the work does not depend on which one matches. */
static u8 pem_b64_code(u8 c) {
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
static const u8 pem_quad_n[4] = {3, 2, 0, 1};

static int pem_match_at(wired_span text, usz i, wired_span nd) {
  usz k = 0;
  while (k < nd.n && text.p[i + k] == nd.p[k]) k++;
  return k == nd.n;
}

/* Find needle nd in text at or after from; 1 and *pos set on a hit. */
static int pem_find(wired_span text, usz from, wired_span nd, usz* pos) {
  for (usz i = from; i + nd.n <= text.n; i++) {
    if (pem_match_at(text, i, nd)) {
      *pos = i;
      return 1;
    }
  }
  return 0;
}

/* Index just past the newline ending the line that starts at or after i. */
static usz pem_line_end(wired_span text, usz i) {
  while (i < text.n && text.p[i] != '\n') i++;
  return i + (usz)(i < text.n);
}

/* Locate "-----BEGIN <label>-----" at or after at; *body = index just past
 * the closing dashes (the rest of the line is CR/LF the decoder skips). */
static int pem_head(wired_span text, usz at, wired_span* label, usz* body) {
  usz b, l;
  if (!pem_find(text, at, wired_span_of(pem_begin_tag, 11), &b)) return 0;
  b += 11;
  if (!pem_find(text, b, wired_span_of(pem_dashes, 5), &l)) return 0;
  *label = wired_span_of(text.p + b, l - b);
  *body  = l + 5;
  return 1;
}

/* Whether n bytes fit both der's capacity and the shift_by lookup below. */
static int pem_emit_fits(const wired_obuf* der, usz n) {
  return n <= 3 && der->len + n <= der->cap;
}

/* Append n bytes (1..3) of the 24-bit group acc to der, high byte first. */
static int pem_emit(wired_obuf* der, u32 acc, usz n) {
  static const u8 shift_by[3] = {16, 8, 0};
  if (!pem_emit_fits(der, n)) return 0;
  for (usz i = 0; i < n; i++) der->p[der->len + i] = (u8)(acc >> shift_by[i]);
  der->len += n;
  return 1;
}

/* A pad may only sit in the last two positions of a quad. */
static int pem_quad_ok(const u8 q[4]) { return q[0] < 64 && q[1] < 64; }

/* Decode one full quad q (codes 0-63 or 64 = pad) into der. */
static int pem_flush(const u8 q[4], wired_obuf* der) {
  u32 acc = 0;
  usz idx = (usz)(q[2] > 63) * 2 + (usz)(q[3] > 63);
  for (usz i = 0; i < 4; i++) acc = (acc << 6) | (u32)(q[i] & 63);
  if (!pem_quad_ok(q)) return 0;
  return pem_emit(der, acc, pem_quad_n[idx]);
}

static int pem_take(u8 code, u8* q, usz* qn, wired_obuf* der) {
  q[(*qn)++] = code;
  if (*qn < 4) return 1;
  *qn = 0;
  return pem_flush(q, der);
}

/* The two branches here key on line structure (CR/LF) and on malformed
 * input, never on a decoded sextet value: a 0-63 code flows into pem_take's
 * arithmetic only. */
static int pem_step(u8 c, u8* q, usz* qn, wired_obuf* der) {
  u8 code = pem_b64_code(c);
  if (code == 65) return 1; /* CR/LF between the wrapped lines */
  if (code == PEM_B64_INVALID) return 0;
  return pem_take(code, q, qn, der);
}

/* All input consumed without error and no partial quad left over. */
static int pem_done(int ok, usz qn) { return ok == 1 && qn == 0; }

/* RFC 4648 4: decode the base64 body (padded quads, CR/LF ignored). */
static int pem_decode(wired_span body, wired_obuf* der) {
  u8  q[4];
  usz qn = 0, i = 0;
  int ok = 1;
  while (ok == 1 && i < body.n) ok = pem_step(body.p[i++], q, &qn, der);
  return pem_done(ok, qn);
}

int wired_pem_next(
    wired_span text, usz* at, wired_span* label, wired_obuf* der) {
  usz body, e;
  if (!pem_head(text, *at, label, &body)) return 0;
  if (!pem_find(text, body, wired_span_of(pem_end_tag, 9), &e)) return 0;
  *at = pem_line_end(text, e);
  return pem_decode(wired_span_of(text.p + body, e - body), der);
}
