#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"

#include "crypto/asymmetric/ecc/ecdsasig/der_int.h"
#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* SEC1 C.5. Concatenate INTEGER r and INTEGER s into body. Each INTEGER TLV is
 * at most 35 octets (0x02, len, 0x00 pad, 32 value), so body holds 2*35.
 * Returns 1 ok with *len set, 0 on encode failure. */
static int sig_body(const u8 r[32], const u8 s[32], u8* body, usz* len) {
  usz rn = 0, sn = 0;
  if (!ecdsasig_encode_integer(r, body, 35, &rn)) return 0;
  if (!ecdsasig_encode_integer(s, body + rn, 35, &sn)) return 0;
  *len = rn + sn;
  return 1;
}

int ecdsasig_encode(
    const u8 r[32], const u8 s[32], u8* out, usz cap, usz* out_len) {
  u8         body[70];
  usz        len = 0;
  wired_obuf o   = obuf_of(out, cap);
  if (!sig_body(r, s, body, &len)) return 0;
  if (!selfcert_der_tlv(DER_SEQUENCE, wired_span_of(body, len), &o)) return 0;
  *out_len = o.len;
  return 1;
}

/* View the SEQUENCE value, requiring it to span exactly all of sig (X.690:
 * no trailing octets after the ECDSA-Sig-Value). */
static int sigv_seq_exact(wired_span sig, wired_span* seq) {
  der_tlv t;
  if (!der_read(sig, &t)) return 0;
  if (t.tag != DER_SEQUENCE) return 0;
  *seq = t.val;
  return t.used == sig.n;
}

/* X.690 8.3.2: a leading 0x00 is allowed only before a top-bit-set octet. */
static int sigv_int_nonminimal(wired_span v) {
  return v.n > 1 && v.p[0] == 0x00 && (v.p[1] & 0x80) == 0;
}

/* Reject an INTEGER value that is empty, negative (SEC1 C.5: r and s are
 * positive), or non-minimally encoded. */
static int sigv_int_bad(wired_span v) {
  if (v.n == 0) return 1;
  if ((v.p[0] & 0x80) != 0) return 1;
  return sigv_int_nonminimal(v);
}

/* Drop the single legitimate 0x00 sign pad. */
static void sigv_strip_pad(wired_span* v) {
  if (v->n > 1 && v->p[0] == 0x00) {
    v->p++;
    v->n--;
  }
}

/* Left-zero-pad v into the n-octet big-endian field out. */
static void sigv_pad_left(u8* out, usz n, wired_span v) {
  for (usz i = 0; i < n; i++) out[i] = 0;
  for (usz i = 0; i < v.n; i++) out[n - v.n + i] = v.p[i];
}

/* v into out if it fits n octets; 0 when the scalar is too wide. */
static int sigv_fit(u8* out, usz n, wired_span v) {
  if (v.n > n) return 0;
  sigv_pad_left(out, n, v);
  return 1;
}

/* One strict INTEGER element of c into an n-octet big-endian field. */
static int sigv_take_int(derseq* c, u8* out, usz n) {
  wired_span v;
  if (!derseq_next_tagged(c, DER_INTEGER, &v)) return 0;
  if (sigv_int_bad(v)) return 0;
  sigv_strip_pad(&v);
  return sigv_fit(out, n, v);
}

/* Exactly two INTEGERs and nothing else inside the SEQUENCE. */
static int sigv_two_ints(derseq* c, u8* r, u8* s, usz n) {
  if (!sigv_take_int(c, r, n)) return 0;
  if (!sigv_take_int(c, s, n)) return 0;
  return c->off == c->len;
}

int ecdsasig_decode(wired_span sig, u8* r, u8* s, usz n) {
  wired_span seq;
  derseq     c;
  if (!sigv_seq_exact(sig, &seq)) return 0;
  derseq_init(&c, seq);
  return sigv_two_ints(&c, r, s, n);
}
