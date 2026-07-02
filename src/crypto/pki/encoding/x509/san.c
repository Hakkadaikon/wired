#include "crypto/pki/encoding/x509/san.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/x509.h"

/* RFC 5280 4.2.1.6. GeneralName dNSName is [2] IMPLICIT IA5String. */
#define SAN_DNSNAME_TAG 0x82

/* id-ce-subjectAltName = 2.5.29.17 */
static const u8 oid_san[] = {0x55, 0x1d, 0x11};

/* ASCII lowercase of one octet (DNS labels are ASCII). */
static u8 san_lower(u8 c) {
  return (c >= 'A' && c <= 'Z') ? (u8)(c | 0x20) : c;
}

/* 1 if the two byte spans of equal length differ nowhere, ASCII-folded. */
static int san_bytes_eq(const u8 *a, const u8 *b, usz n) {
  usz diff = 0;
  for (usz i = 0; i < n; i++) diff |= (usz)(san_lower(a[i]) ^ san_lower(b[i]));
  return diff == 0;
}

/* RFC 6125 6.4.1: hostname comparison is ASCII case-insensitive. */
static int dns_eq(quic_span a, quic_span b) {
  return a.n == b.n && san_bytes_eq(a.p, b.p, a.n);
}

/* Offset of the first '.' in name, or its length if none. */
static usz first_dot(quic_span name) {
  usz i = 0;
  while (i < name.n && name.p[i] != '.') i++;
  return i;
}

/* RFC 6125 6.4.3. A SAN entry starts with the "*." wildcard label. */
static int is_wildcard(quic_span entry) {
  return entry.n >= 2 && entry.p[0] == '*' && entry.p[1] == '.';
}

/* RFC 6125 6.4.3. A "*." entry matches host iff the wildcard label covers
 * exactly the host's first label and the remainders are equal. */
static int wildcard_match(quic_span entry, quic_span host) {
  usz hdot = first_dot(host);
  if (!is_wildcard(entry) || hdot >= host.n) return 0;
  return dns_eq(
      quic_span_of(entry.p + 1, entry.n - 1),
      quic_span_of(host.p + hdot, host.n - hdot));
}

/* One GeneralName dNSName entry matches the hostname. */
static int entry_matches(quic_span e, quic_span host) {
  return dns_eq(e, host) || wildcard_match(e, host);
}

/* RFC 5280 4.2.1.6. The GeneralNames SEQUENCE value inside the extnValue. */
static int san_names(quic_span tbs, quic_span *names) {
  quic_span san;
  if (!quic_x509_find_ext(tbs, quic_span_of(oid_san, sizeof(oid_san)), &san))
    return 0;
  return quic_der_seq(san, names);
}

/* A GeneralName is a dNSName that matches the hostname. */
static int dnsname_matches(u8 tag, quic_span e, quic_span host) {
  return tag == SAN_DNSNAME_TAG && entry_matches(e, host);
}

/* RFC 5280 4.2.1.6. Scan the GeneralNames for a matching dNSName. */
static int names_match(quic_span gn, quic_span host) {
  quic_derseq names;
  u8          tag;
  quic_span   e;
  quic_derseq_init(&names, gn);
  while (quic_derseq_next(&names, &tag, &e))
    if (dnsname_matches(tag, e, host)) return 1;
  return 0;
}

int quic_x509_san_matches(quic_span tbs, quic_span hostname) {
  quic_span gn;
  if (!san_names(tbs, &gn)) return 0;
  return names_match(gn, hostname);
}
