#include "crypto/pki/encoding/pem/pem.h"

/* RFC 7468 2: block markers. u8 arrays so spans view them directly. */
static const u8 pem_begin_tag[] = "-----BEGIN ";
static const u8 pem_end_tag[]   = "-----END ";
static const u8 pem_dashes[]    = "-----";

/* RFC 4648 4 reverse alphabet: 0-63 = sextet value, 64 = pad '=',
 * 65 = skip (CR/LF), 66 = invalid. */
static const u8 pem_b64[256] = {
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 65, 66, 66, 65, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 62, 66, 66, 66, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 66, 66, 66, 64, 66, 66, 66, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 66, 66, 66, 66,
    66, 66, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66,
};

/* Output byte count of a final quad by pad shape:
 * index = (q[2] is pad)*2 + (q[3] is pad); a pad in q[2] alone is invalid. */
static const u8 pem_quad_n[4] = {3, 2, 0, 1};

static int pem_match_at(quic_span text, usz i, quic_span nd) {
  usz k = 0;
  while (k < nd.n && text.p[i + k] == nd.p[k]) k++;
  return k == nd.n;
}

/* Find needle nd in text at or after from; 1 and *pos set on a hit. */
static int pem_find(quic_span text, usz from, quic_span nd, usz *pos) {
  for (usz i = from; i + nd.n <= text.n; i++) {
    if (pem_match_at(text, i, nd)) {
      *pos = i;
      return 1;
    }
  }
  return 0;
}

/* Index just past the newline ending the line that starts at or after i. */
static usz pem_line_end(quic_span text, usz i) {
  while (i < text.n && text.p[i] != '\n') i++;
  return i + (usz)(i < text.n);
}

/* Locate "-----BEGIN <label>-----" at or after at; *body = index just past
 * the closing dashes (the rest of the line is CR/LF the decoder skips). */
static int pem_head(quic_span text, usz at, quic_span *label, usz *body) {
  usz b, l;
  if (!pem_find(text, at, quic_span_of(pem_begin_tag, 11), &b)) return 0;
  b += 11;
  if (!pem_find(text, b, quic_span_of(pem_dashes, 5), &l)) return 0;
  *label = quic_span_of(text.p + b, l - b);
  *body  = l + 5;
  return 1;
}

/* Append n bytes (1..3) of the 24-bit group acc to der, high byte first. */
static int pem_emit(quic_obuf *der, u32 acc, usz n) {
  if (der->len + n > der->cap) return 0;
  for (usz i = 0; i < n; i++) {
    der->p[der->len + i] = (u8)(acc >> (16 - 8 * i));
  }
  der->len += n;
  return 1;
}

/* A pad may only sit in the last two positions of a quad. */
static int pem_quad_ok(const u8 q[4]) { return q[0] < 64 && q[1] < 64; }

/* Decode one full quad q (codes 0-63 or 64 = pad) into der. */
static int pem_flush(const u8 q[4], quic_obuf *der) {
  u32 acc = 0;
  usz idx = (usz)(q[2] > 63) * 2 + (usz)(q[3] > 63);
  for (usz i = 0; i < 4; i++) acc = (acc << 6) | (u32)(q[i] & 63);
  if (!pem_quad_ok(q)) return 0;
  return pem_emit(der, acc, pem_quad_n[idx]);
}

static int pem_take(u8 code, u8 *q, usz *qn, quic_obuf *der) {
  q[(*qn)++] = code;
  if (*qn < 4) return 1;
  *qn = 0;
  return pem_flush(q, der);
}

static int pem_step(u8 c, u8 *q, usz *qn, quic_obuf *der) {
  u8 code = pem_b64[c];
  if (code == 65) return 1; /* CR/LF between the wrapped lines */
  if (code == 66) return 0;
  return pem_take(code, q, qn, der);
}

/* All input consumed without error and no partial quad left over. */
static int pem_done(int ok, usz qn) { return ok == 1 && qn == 0; }

/* RFC 4648 4: decode the base64 body (padded quads, CR/LF ignored). */
static int pem_decode(quic_span body, quic_obuf *der) {
  u8  q[4];
  usz qn = 0, i = 0;
  int ok = 1;
  while (ok == 1 && i < body.n) ok = pem_step(body.p[i++], q, &qn, der);
  return pem_done(ok, qn);
}

int wired_pem_next(quic_span text, usz *at, quic_span *label, quic_obuf *der) {
  usz body, e;
  if (!pem_head(text, *at, label, &body)) return 0;
  if (!pem_find(text, body, quic_span_of(pem_end_tag, 9), &e)) return 0;
  *at = pem_line_end(text, e);
  return pem_decode(quic_span_of(text.p + body, e - body), der);
}
