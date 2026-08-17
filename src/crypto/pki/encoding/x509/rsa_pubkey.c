#include "crypto/pki/encoding/x509/rsa_pubkey.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 8017 A.1.1. A positive INTEGER carries one 0x00 pad when its top bit
 * is set; strip it so the value is the bare big-endian magnitude. */
static void strip_pad(wired_span* v) {
  if (v->n > 1 && v->p[0] == 0x00) {
    v->p++;
    v->n--;
  }
}

/* Read one INTEGER from the cursor, stripping a sign pad. */
static int next_int(quic_derseq* c, wired_span* v) {
  if (!quic_derseq_next_tagged(c, QUIC_DER_INTEGER, v)) return 0;
  if (v->n == 0) return 0;
  strip_pad(v);
  return 1;
}

/* 1 if the BIT STRING value leads with the 0x00 unused-bits octet. */
static int has_bitstr_prefix(wired_span key) {
  return key.n >= 1 && key.p[0] == 0x00;
}

/* Step over the BIT STRING unused-bits octet into the RSAPublicKey SEQUENCE. */
static int into_rsa_seq(wired_span key, quic_derseq* c) {
  wired_span seq;
  if (!has_bitstr_prefix(key)) return 0;
  quic_derseq_init(c, wired_span_of(key.p + 1, key.n - 1));
  if (!quic_derseq_next_tagged(c, QUIC_DER_SEQUENCE, &seq)) return 0;
  quic_derseq_init(c, seq);
  return 1;
}

/* RFC 8017 3.1 floor: a modulus under 2048 bits is factorable at practical
 * cost and is rejected. */
#define RSA_PUBKEY_MIN_N 256

/* X.690 8.3.2 canonical leading octet (no redundant zero after the one sign
 * pad) and an odd low octet. Caller guarantees a non-empty value. */
static int rpk_canon_odd(wired_span v) {
  return v.p[0] != 0x00 && (v.p[v.n - 1] & 1);
}

/* n is canonical, odd (a product of odd primes), and >= 2048 bits. */
static int rpk_n_valid(wired_span n) {
  return n.n >= RSA_PUBKEY_MIN_N && rpk_canon_odd(n);
}

/* RFC 8017 3.1. e >= 3 (a single octet of 0, 1, or 2 is rejected). */
static int rpk_e_min(wired_span e) { return e.n > 1 || e.p[0] >= 3; }

/* 3 <= e < 2^64. */
static int rpk_e_range(wired_span e) {
  return e.n >= 1 && e.n <= 8 && rpk_e_min(e);
}

/* e is bounded, canonical, and odd. */
static int rpk_e_valid(wired_span e) {
  return rpk_e_range(e) && rpk_canon_odd(e);
}

static int rpk_valid(wired_span n, wired_span e) {
  return rpk_n_valid(n) && rpk_e_valid(e);
}

/* RFC 8017 A.1.1. Both INTEGERs of RSAPublicKey { n, e } from the cursor. */
static int rpk_read(quic_derseq* c, wired_span* n, wired_span* e) {
  if (!next_int(c, n)) return 0;
  return next_int(c, e);
}

int quic_x509_rsa_pubkey(wired_span spki_key, wired_span* n, wired_span* e) {
  quic_derseq c;
  if (!into_rsa_seq(spki_key, &c)) return 0;
  if (!rpk_read(&c, n, e)) return 0;
  return rpk_valid(*n, *e);
}
