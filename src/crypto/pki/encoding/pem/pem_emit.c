#include "crypto/pki/encoding/pem/pem_impl.h"

static int pem_emit_fits(const wired_obuf* der, usz n);
static int pem_emit(wired_obuf* der, u32 acc, usz n);
static int pem_quad_ok(const u8 q[4]);
static int pem_flush(const u8 q[4], wired_obuf* der);
static int pem_take(u8 code, u8* q, usz* qn, wired_obuf* der);
static int pem_step(u8 c, u8* q, usz* qn, wired_obuf* der);
static int pem_done(int ok, usz qn);
static int pem_decode(wired_span body, wired_obuf* der);

/* Whether n bytes fit both der's capacity and the shift_by lookup below. */
static int pem_emit_fits(const wired_obuf* der, usz n) {
  return n <= 3 && der->len + n <= der->cap;
}

/* Append n bytes (1..3) of the 24-bit group acc to der, high byte first. */
static int pem_emit(wired_obuf* der, u32 acc, usz n) {
  static const u8 shift_by[3] = {16, 8, 0};
  if (!pem_emit_fits(der, n)) {
    return 0;
  }
  for (usz i = 0; i < n; i++) {
    der->p[der->len + i] = (u8)(acc >> shift_by[i]);
  }
  der->len += n;
  return 1;
}

/* A pad may only sit in the last two positions of a quad. */
static int pem_quad_ok(const u8 q[4]) { return q[0] < 64 && q[1] < 64; }

/* Decode one full quad q (codes 0-63 or 64 = pad) into der. */
static int pem_flush(const u8 q[4], wired_obuf* der) {
  u32 acc = 0;
  usz idx = (usz)(q[2] > 63) * 2 + (usz)(q[3] > 63);
  for (usz i = 0; i < 4; i++) {
    acc = (acc << 6) | (u32)(q[i] & 63);
  }
  if (!pem_quad_ok(q)) {
    return 0;
  }
  return pem_emit(der, acc, pem_quad_n[idx]);
}

static int pem_take(u8 code, u8* q, usz* qn, wired_obuf* der) {
  q[(*qn)++] = code;
  if (*qn < 4) {
    return 1;
  }
  *qn = 0;
  return pem_flush(q, der);
}

/* The two branches here key on line structure (CR/LF) and on malformed
 * input, never on a decoded sextet value: a 0-63 code flows into pem_take's
 * arithmetic only. */
static int pem_step(u8 c, u8* q, usz* qn, wired_obuf* der) {
  u8 code = pem_b64_code(c);
  if (code == 65) {
    return 1; /* CR/LF between the wrapped lines */
  }
  if (code == PEM_B64_INVALID) {
    return 0;
  }
  return pem_take(code, q, qn, der);
}

/* All input consumed without error and no partial quad left over. */
static int pem_done(int ok, usz qn) { return ok == 1 && qn == 0; }

/* RFC 4648 4: decode the base64 body (padded quads, CR/LF ignored). */
static int pem_decode(wired_span body, wired_obuf* der) {
  u8  q[4];
  usz qn = 0, i = 0;
  int ok = 1;
  while (ok == 1 && i < body.n) {
    ok = pem_step(body.p[i++], q, &qn, der);
  }
  return pem_done(ok, qn);
}

int wired_pem_next(
    wired_span text, usz* at, wired_span* label, wired_obuf* der) {
  usz body, e;
  if (!pem_head(text, *at, label, &body)) {
    return 0;
  }
  if (!pem_find(text, body, wired_span_of(pem_end_tag, 9), &e)) {
    return 0;
  }
  *at = pem_line_end(text, e);
  return pem_decode(wired_span_of(text.p + body, e - body), der);
}
