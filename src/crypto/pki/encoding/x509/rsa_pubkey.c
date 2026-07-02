#include "crypto/pki/encoding/x509/rsa_pubkey.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 8017 A.1.1. A positive INTEGER carries one 0x00 pad when its top bit
 * is set; strip it so the value is the bare big-endian magnitude. */
static void strip_pad(const u8 **v, usz *len) {
  if (*len > 1 && (*v)[0] == 0x00) {
    (*v)++;
    (*len)--;
  }
}

/* Read the next element of c, requiring tag want. 1 ok, 0 otherwise. */
static int next_tag(quic_derseq *c, u8 want, const u8 **v, usz *len) {
  u8 tag;
  if (!quic_derseq_next(c, &tag, v, len)) return 0;
  return tag == want;
}

/* Read one INTEGER from the cursor, stripping a sign pad. */
static int next_int(quic_derseq *c, const u8 **v, usz *len) {
  if (!next_tag(c, QUIC_DER_INTEGER, v, len)) return 0;
  if (*len == 0) return 0;
  strip_pad(v, len);
  return 1;
}

/* 1 if the BIT STRING value leads with the 0x00 unused-bits octet. */
static int has_bitstr_prefix(const u8 *key, usz key_len) {
  return key_len >= 1 && key[0] == 0x00;
}

/* Step over the BIT STRING unused-bits octet into the RSAPublicKey SEQUENCE. */
static int into_rsa_seq(const u8 *key, usz key_len, quic_derseq *c) {
  const u8 *seq;
  usz       seq_len;
  if (!has_bitstr_prefix(key, key_len)) return 0;
  quic_derseq_init(c, key + 1, key_len - 1);
  if (!next_tag(c, QUIC_DER_SEQUENCE, &seq, &seq_len)) return 0;
  quic_derseq_init(c, seq, seq_len);
  return 1;
}

/* RFC 8017 3.1 floor: a modulus under 2048 bits is factorable at practical
 * cost and is rejected. */
#define RSA_PUBKEY_MIN_N 256

/* X.690 8.3.2 canonical leading octet (no redundant zero after the one sign
 * pad) and an odd low octet. Caller guarantees len >= 1. */
static int rpk_canon_odd(const u8 *v, usz len) {
  return v[0] != 0x00 && (v[len - 1] & 1);
}

/* n is canonical, odd (a product of odd primes), and >= 2048 bits. */
static int rpk_n_valid(const u8 *n, usz len) {
  return len >= RSA_PUBKEY_MIN_N && rpk_canon_odd(n, len);
}

/* RFC 8017 3.1. e >= 3 (a single octet of 0, 1, or 2 is rejected). */
static int rpk_e_min(const u8 *e, usz len) { return len > 1 || e[0] >= 3; }

/* 3 <= e < 2^64. */
static int rpk_e_range(const u8 *e, usz len) {
  return len >= 1 && len <= 8 && rpk_e_min(e, len);
}

/* e is bounded, canonical, and odd. */
static int rpk_e_valid(const u8 *e, usz len) {
  return rpk_e_range(e, len) && rpk_canon_odd(e, len);
}

static int rpk_valid(const u8 *n, usz n_len, const u8 *e, usz e_len) {
  return rpk_n_valid(n, n_len) && rpk_e_valid(e, e_len);
}

/* RFC 8017 A.1.1. Both INTEGERs of RSAPublicKey { n, e } from the cursor. */
static int rpk_read(
    quic_derseq *c, const u8 **n, usz *n_len, const u8 **e, usz *e_len) {
  if (!next_int(c, n, n_len)) return 0;
  return next_int(c, e, e_len);
}

int quic_x509_rsa_pubkey(
    const u8  *spki_key,
    usz        key_len,
    const u8 **n,
    usz       *n_len,
    const u8 **e,
    usz       *e_len) {
  quic_derseq c;
  if (!into_rsa_seq(spki_key, key_len, &c)) return 0;
  if (!rpk_read(&c, n, n_len, e, e_len)) return 0;
  return rpk_valid(*n, *n_len, *e, *e_len);
}
