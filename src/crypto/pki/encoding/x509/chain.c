#include "crypto/pki/encoding/x509/chain.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/x509.h"

/* RFC 5280 4.1. tbs elements before issuer (version excluded): serialNumber,
 * signature. */
#define ISSUER_SKIP 2
/* RFC 5280 4.1. Between issuer and subject: validity. */
#define SUBJECT_SKIP 1

/* Read the next element as a whole TLV (header included) by spanning the
 * cursor's offsets. Requires a SEQUENCE tag. 1 ok, 0 otherwise. */
static int ch_next_seq_tlv(quic_derseq* c, quic_span* tlv) {
  u8        tag;
  quic_span val;
  usz       start = c->off;
  if (!quic_derseq_next(c, &tag, &val)) return 0;
  if (tag != QUIC_DER_SEQUENCE) return 0;
  *tlv = quic_span_of(c->p + start, c->off - start);
  return 1;
}

/* Position c before the issuer Name (after version, serialNumber, signature).
 */
static int ch_at_issuer(quic_span tbs, quic_derseq* c) {
  return quic_x509_tbs_cursor(tbs, c) && quic_derseq_skip(c, ISSUER_SKIP);
}

int quic_x509_issuer(quic_span tbs, quic_span* issuer) {
  quic_derseq c;
  return ch_at_issuer(tbs, &c) && ch_next_seq_tlv(&c, issuer);
}

/* Position c just past the issuer Name, before validity. */
static int ch_after_issuer(quic_span tbs, quic_derseq* c) {
  quic_span issuer;
  return ch_at_issuer(tbs, c) && ch_next_seq_tlv(c, &issuer);
}

/* Skip validity, then read the subject Name TLV. */
static int ch_skip_to_subject(quic_derseq* c, quic_span* subject) {
  return quic_derseq_skip(c, SUBJECT_SKIP) && ch_next_seq_tlv(c, subject);
}

int quic_x509_subject(quic_span tbs, quic_span* subject) {
  quic_derseq c;
  return ch_after_issuer(tbs, &c) && ch_skip_to_subject(&c, subject);
}

/* 1 if the two byte spans of equal length differ nowhere. */
static int ch_bytes_eq(const u8* a, const u8* b, usz n) {
  usz diff = 0;
  for (usz i = 0; i < n; i++) diff |= (usz)(a[i] ^ b[i]);
  return diff == 0;
}

int quic_x509_dn_equal(quic_span a, quic_span b) {
  return a.n == b.n && ch_bytes_eq(a.p, b.p, a.n);
}
