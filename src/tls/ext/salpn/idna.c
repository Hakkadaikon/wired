#include "tls/ext/salpn/idna.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "tls/ext/salpn/punycode.h"

/* RFC 1035 2.3.4: a name is at most 255 octets, a label at most 63. */
#define IDNA_HOST_MAX 255
#define IDNA_LABEL_MAX 63
#define IDNA_BAD 0xFFFFFFFFu

/* RFC 3629 3: UTF-8 sequence length by lead byte >> 3 (0 = not a lead). */
static const u8 IDNA_U8LEN[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                  1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
                                  0, 0, 2, 2, 2, 2, 3, 3, 4, 0};
/* The lead byte's payload bits, and the least code point (no overlong
 * form), by sequence length. */
static const u8  IDNA_U8MASK[5] = {0, 0x7F, 0x1F, 0x0F, 0x07};
static const u32 IDNA_U8MIN[5]  = {0, 0, 0x80, 0x800, 0x10000};

/* One continuation byte folded in; IDNA_BAD stays bad. */
static u32 idna_u8_cont(u32 v, u8 c) {
  return (c & 0xC0) == 0x80 && v != IDNA_BAD ? (v << 6 | (c & 0x3Fu))
                                             : IDNA_BAD;
}

/* A scalar value (RFC 3629 3: no surrogate, at most 0x10FFFF) in its
 * shortest form. */
static int idna_cp_ok(u32 v, usz len) {
  return v >= IDNA_U8MIN[len] && v <= 0x10FFFF && v - 0xD800 > 0x7FF;
}

/* The len-byte sequence at s folded into one value (IDNA_BAD on a bad
 * continuation byte). */
static u32 idna_u8_fold(const u8* s, usz len) {
  u32 v = s[0] & IDNA_U8MASK[len];
  for (usz i = 1; i < len; i++) {
    v = idna_u8_cont(v, s[i]);
  }
  return v;
}

/* A lead byte (len != 0) whose whole sequence is within the n bytes. */
static int idna_len_ok(usz len, usz n) { return len != 0 && len <= n; }

/* Decode the code point at s (n bytes left) into *cp; returns its byte
 * length, or 0 on malformed UTF-8. */
static usz idna_utf8_one(const u8* s, usz n, u32* cp) {
  usz len = IDNA_U8LEN[s[0] >> 3];
  if (!idna_len_ok(len, n)) {
    return 0;
  }
  *cp = idna_u8_fold(s, len);
  return idna_cp_ok(*cp, len) ? len : 0;
}

/* Still decoding: the last code point was good and bytes remain. */
static int idna_decode_more(usz k, usz at, usz n) { return k != 0 && at < n; }

/* The label's code points into cps (room for l.n); 0 on bad UTF-8 or an
 * empty label. */
static usz idna_decode_label(wired_span l, u32* cps) {
  usz n = 0, at = 0, k = 1;
  while (idna_decode_more(k, at, l.n)) {
    k = idna_utf8_one(l.p + at, l.n - at, &cps[n++]);
    at += k;
  }
  return k != 0 ? n : 0;
}

/* RFC 5891 4.4 / RFC 3492: "xn--" + the Punycode of cps, within one
 * label's 63 octets. */
static usz idna_alabel(const u32* cps, usz n, u8* out, usz cap) {
  usz k;
  if (cap < 4) {
    return 0;
  }
  bytes_memcpy(out, "xn--", 4);
  k = salpn_punycode_encode(
      cps, n, out + 4, (usz)u64_min(cap - 4, IDNA_LABEL_MAX - 4));
  return k ? 4 + k : 0;
}

/* An all-ASCII label (already an A-label, or never needed one) as is. */
static usz idna_copy(wired_span l, u8* out, usz cap) {
  if (l.n > cap) {
    return 0;
  }
  bytes_memcpy(out, l.p, l.n);
  return l.n;
}

/* One label in A-label form: code points all below 0x80 copy through,
 * otherwise it is a U-label and gets Punycode-encoded. */
static usz idna_label(wired_span l, u8* out, usz cap) {
  u32 cps[IDNA_HOST_MAX];
  usz n = idna_decode_label(l, cps);
  if (n == 0) {
    return 0;
  }
  return n == l.n ? idna_copy(l, out, cap) : idna_alabel(cps, n, out, cap);
}

typedef struct {
  wired_span host;
  usz        at; /* next label's offset in host */
  u8*        out;
  usz        cap;
  usz        len;
  int        ok;
} idna_w;

static usz idna_label_end(wired_span h, usz at) {
  while (at < h.n && h.p[at] != '.') {
    at++;
  }
  return at;
}

static int idna_put_dot(idna_w* w) {
  if (w->len >= w->cap) {
    return 0;
  }
  w->out[w->len++] = '.';
  return 1;
}

/* Convert the label at w->at, then the dot after it if any. */
static void idna_step(idna_w* w) {
  usz end = idna_label_end(w->host, w->at);
  usz k   = idna_label(
      wired_span_of(w->host.p + w->at, end - w->at), w->out + w->len,
      w->cap - w->len);
  w->ok = k != 0;
  w->len += k;
  w->at = end + 1;
  if (w->ok && end < w->host.n) {
    w->ok = idna_put_dot(w);
  }
}

static int idna_more(const idna_w* w) { return w->ok && w->at < w->host.n; }

usz salpn_idna_to_ascii(wired_span host, u8* out, usz cap) {
  idna_w w = {host, 0, out, cap, 0, host.n <= IDNA_HOST_MAX};
  while (idna_more(&w)) {
    idna_step(&w);
  }
  return w.ok ? w.len : 0;
}
