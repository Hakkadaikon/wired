#include "crypto/pki/encoding/x509/chain.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT, optional and default v1. */
#define X509_VERSION_TAG 0xa0
/* RFC 5280 4.1. tbs elements before issuer (version excluded): serialNumber,
 * signature. */
#define ISSUER_SKIP 2
/* RFC 5280 4.1. Between issuer and subject: validity. */
#define SUBJECT_SKIP 1

/* The tbs SEQUENCE value (after its own header). 0 if not a SEQUENCE. */
static int ch_tbs_value(const u8 *tbs, usz tbs_len, const u8 **v, usz *vlen) {
  u8  tag;
  usz used;
  if (!quic_der_read(tbs, tbs_len, &tag, v, vlen, &used)) return 0;
  return tag == QUIC_DER_SEQUENCE;
}

/* Drop the optional version element, leaving the cursor before serialNumber. */
static int ch_skip_version(quic_derseq *c) {
  u8        tag;
  const u8 *val;
  usz       vlen;
  if (c->off < c->len && c->p[c->off] == X509_VERSION_TAG)
    return quic_derseq_next(c, &tag, &val, &vlen);
  return 1;
}

/* Advance the cursor past n elements. 1 if all were present. */
static int ch_skip_n(quic_derseq *c, usz n) {
  u8        tag;
  const u8 *val;
  usz       vlen;
  for (usz i = 0; i < n; i++)
    if (!quic_derseq_next(c, &tag, &val, &vlen)) return 0;
  return 1;
}

/* Read the next element as a whole TLV (header included) by spanning the
 * cursor's offsets. Requires a SEQUENCE tag. 1 ok, 0 otherwise. */
static int ch_next_seq_tlv(quic_derseq *c, const u8 **tlv, usz *tlv_len) {
  u8        tag;
  const u8 *val;
  usz       vlen, start = c->off;
  if (!quic_derseq_next(c, &tag, &val, &vlen)) return 0;
  if (tag != QUIC_DER_SEQUENCE) return 0;
  *tlv     = c->p + start;
  *tlv_len = c->off - start;
  return 1;
}

/* Position c before serialNumber, inside the tbs SEQUENCE value. */
static int ch_tbs_cursor(const u8 *tbs, usz tbs_len, quic_derseq *c) {
  const u8 *v;
  usz       vlen;
  if (!ch_tbs_value(tbs, tbs_len, &v, &vlen)) return 0;
  quic_derseq_init(c, v, vlen);
  return ch_skip_version(c);
}

/* Position c before the issuer Name (after version, serialNumber, signature).
 */
static int ch_at_issuer(const u8 *tbs, usz tbs_len, quic_derseq *c) {
  return ch_tbs_cursor(tbs, tbs_len, c) && ch_skip_n(c, ISSUER_SKIP);
}

int quic_x509_issuer(const u8 *tbs, usz tbs_len, const u8 **issuer, usz *len) {
  quic_derseq c;
  return ch_at_issuer(tbs, tbs_len, &c) && ch_next_seq_tlv(&c, issuer, len);
}

/* Position c just past the issuer Name, before validity. */
static int ch_after_issuer(const u8 *tbs, usz tbs_len, quic_derseq *c) {
  const u8 *issuer;
  usz       ilen;
  return ch_at_issuer(tbs, tbs_len, c) && ch_next_seq_tlv(c, &issuer, &ilen);
}

/* Skip validity, then read the subject Name TLV. */
static int ch_skip_to_subject(quic_derseq *c, const u8 **subject, usz *len) {
  return ch_skip_n(c, SUBJECT_SKIP) && ch_next_seq_tlv(c, subject, len);
}

int quic_x509_subject(
    const u8 *tbs, usz tbs_len, const u8 **subject, usz *len) {
  quic_derseq c;
  return ch_after_issuer(tbs, tbs_len, &c) &&
         ch_skip_to_subject(&c, subject, len);
}

/* 1 if the two byte spans of equal length differ nowhere. */
static int ch_bytes_eq(const u8 *a, const u8 *b, usz n) {
  usz diff = 0;
  for (usz i = 0; i < n; i++) diff |= (usz)(a[i] ^ b[i]);
  return diff == 0;
}

int quic_x509_dn_equal(const u8 *a, usz alen, const u8 *b, usz blen) {
  return alen == blen && ch_bytes_eq(a, b, alen);
}
