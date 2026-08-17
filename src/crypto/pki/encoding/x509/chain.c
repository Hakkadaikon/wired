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
static int ch_next_seq_tlv(derseq* c, wired_span* tlv) {
  u8         tag;
  wired_span val;
  usz        start = c->off;
  if (!derseq_next(c, &tag, &val)) return 0;
  if (tag != QUIC_DER_SEQUENCE) return 0;
  *tlv = wired_span_of(c->p + start, c->off - start);
  return 1;
}

/* Position c before the issuer Name (after version, serialNumber, signature).
 */
static int ch_at_issuer(wired_span tbs, derseq* c) {
  return x509_tbs_cursor(tbs, c) && derseq_skip(c, ISSUER_SKIP);
}

int x509_issuer(wired_span tbs, wired_span* issuer) {
  derseq c;
  return ch_at_issuer(tbs, &c) && ch_next_seq_tlv(&c, issuer);
}

/* Position c just past the issuer Name, before validity. */
static int ch_after_issuer(wired_span tbs, derseq* c) {
  wired_span issuer;
  return ch_at_issuer(tbs, c) && ch_next_seq_tlv(c, &issuer);
}

/* Skip validity, then read the subject Name TLV. */
static int ch_skip_to_subject(derseq* c, wired_span* subject) {
  return derseq_skip(c, SUBJECT_SKIP) && ch_next_seq_tlv(c, subject);
}

int x509_subject(wired_span tbs, wired_span* subject) {
  derseq c;
  return ch_after_issuer(tbs, &c) && ch_skip_to_subject(&c, subject);
}

/* 1 if the two byte spans of equal length differ nowhere. */
static int ch_bytes_eq(const u8* a, const u8* b, usz n) {
  usz diff = 0;
  for (usz i = 0; i < n; i++) diff |= (usz)(a[i] ^ b[i]);
  return diff == 0;
}

int x509_dn_equal(wired_span a, wired_span b) {
  return a.n == b.n && ch_bytes_eq(a.p, b.p, a.n);
}
