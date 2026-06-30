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

int quic_x509_rsa_pubkey(
    const u8  *spki_key,
    usz        key_len,
    const u8 **n,
    usz       *n_len,
    const u8 **e,
    usz       *e_len) {
  quic_derseq c;
  if (!into_rsa_seq(spki_key, key_len, &c)) return 0;
  if (!next_int(&c, n, n_len)) return 0;
  return next_int(&c, e, e_len);
}
