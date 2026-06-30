#include "crypto/pki/encoding/x509/x509.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 5280 4.1.1.2. signatureAlgorithm ::= SEQUENCE { algorithm OID, ... }.
 * Extract the OID value from the AlgorithmIdentifier blob. */
static int alg_oid(const u8 *alg, usz alg_len, const u8 **oid, usz *oid_len) {
  quic_derseq c;
  u8          tag;
  quic_derseq_init(&c, alg, alg_len);
  if (!quic_derseq_next(&c, &tag, oid, oid_len)) return 0;
  return tag == QUIC_DER_OID;
}

/* Read one element of the outer SEQUENCE, keeping its header-included span
 * (the signed bytes for tbsCertificate). Advances *off. */
static int outer_next(
    const u8  *v,
    usz        n,
    usz       *off,
    const u8 **start,
    u8        *tag,
    const u8 **val,
    usz       *vlen) {
  usz used;
  if (*off >= n) return 0;
  *start = v + *off;
  if (!quic_der_read(*start, n - *off, tag, val, vlen, &used)) return 0;
  *off += used;
  return 1;
}

static int field_is(u8 tag, u8 want) { return tag == want; }

/* RFC 5280 4.1. tbsCertificate: keep the header-included span (signed bytes).
 */
static int take_tbs(const u8 *seq, usz seq_len, usz *off, quic_x509 *out) {
  u8        tag;
  const u8 *val;
  usz       vlen;
  if (!outer_next(seq, seq_len, off, &out->tbs, &tag, &val, &vlen)) return 0;
  if (!field_is(tag, QUIC_DER_SEQUENCE)) return 0;
  out->tbs_len = (val - out->tbs) + vlen;
  return 1;
}

/* RFC 5280 4.1.1.2. signatureAlgorithm: pull out its OID. */
static int take_alg(const u8 *seq, usz seq_len, usz *off, quic_x509 *out) {
  u8        tag;
  const u8 *start, *alg;
  usz       alg_len;
  if (!outer_next(seq, seq_len, off, &start, &tag, &alg, &alg_len)) return 0;
  if (!field_is(tag, QUIC_DER_SEQUENCE)) return 0;
  return alg_oid(alg, alg_len, &out->sig_alg_oid, &out->sig_alg_len);
}

/* RFC 5280 4.1.1.3. signatureValue: a BIT STRING. */
static int take_sig(const u8 *seq, usz seq_len, usz *off, quic_x509 *out) {
  u8        tag;
  const u8 *start;
  if (!outer_next(seq, seq_len, off, &start, &tag, &out->sig, &out->sig_len))
    return 0;
  return field_is(tag, QUIC_DER_BIT_STRING);
}

/* The outer SEQUENCE value and its length, or 0 if the tag is wrong. */
static int outer_seq(const u8 *cert, usz len, const u8 **seq, usz *seq_len) {
  u8  tag;
  usz used;
  if (!quic_der_read(cert, len, &tag, seq, seq_len, &used)) return 0;
  return field_is(tag, QUIC_DER_SEQUENCE);
}

/* RFC 5280 4.1. The three fields in order: tbs, algorithm, signature. */
static int take_fields(const u8 *seq, usz seq_len, quic_x509 *out) {
  usz off = 0;
  return take_tbs(seq, seq_len, &off, out) &&
         take_alg(seq, seq_len, &off, out) && take_sig(seq, seq_len, &off, out);
}

int quic_x509_parse(const u8 *cert, usz len, quic_x509 *out) {
  const u8 *seq;
  usz       seq_len;
  return outer_seq(cert, len, &seq, &seq_len) && take_fields(seq, seq_len, out);
}
