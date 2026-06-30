#include "crypto/pki/encoding/x509/san.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT, optional and default v1. */
#define X509_VERSION_TAG 0xa0
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT. */
#define X509_EXTENSIONS_TAG 0xa3
/* RFC 5280 4.1. tbs elements before extensions (version excluded). */
#define EXT_SKIP 6
/* RFC 5280 4.2.1.6. GeneralName dNSName is [2] IMPLICIT IA5String. */
#define SAN_DNSNAME_TAG 0x82

/* id-ce-subjectAltName = 2.5.29.17 */
static const u8 oid_san[] = {0x55, 0x1d, 0x11};

/* The tbs SEQUENCE value (after its own header). 0 if not a SEQUENCE. */
static int san_tbs_value(const u8 *tbs, usz tbs_len, const u8 **v, usz *vlen) {
  u8  tag;
  usz used;
  if (!quic_der_read(tbs, tbs_len, &tag, v, vlen, &used)) return 0;
  return tag == QUIC_DER_SEQUENCE;
}

/* Drop the optional version element. */
static int san_skip_version(quic_derseq *c) {
  u8        tag;
  const u8 *val;
  usz       vlen;
  if (c->off < c->len && c->p[c->off] == X509_VERSION_TAG)
    return quic_derseq_next(c, &tag, &val, &vlen);
  return 1;
}

/* Advance the cursor past n elements. 1 if all were present. */
static int san_skip_n(quic_derseq *c, usz n) {
  u8        tag;
  const u8 *val;
  usz       vlen;
  for (usz i = 0; i < n; i++)
    if (!quic_derseq_next(c, &tag, &val, &vlen)) return 0;
  return 1;
}

/* Position the cursor before the extensions [3] element. */
static int san_at_extensions(const u8 *tbs, usz tbs_len, quic_derseq *c) {
  const u8 *v;
  usz       vlen;
  if (!san_tbs_value(tbs, tbs_len, &v, &vlen)) return 0;
  quic_derseq_init(c, v, vlen);
  return san_skip_version(c) && san_skip_n(c, EXT_SKIP);
}

/* The SEQUENCE value wrapped directly inside the given bytes. */
static int san_unwrap_seq(const u8 *val, usz vlen, const u8 **seq, usz *slen) {
  u8  tag;
  usz used;
  if (!quic_der_read(val, vlen, &tag, seq, slen, &used)) return 0;
  return tag == QUIC_DER_SEQUENCE;
}

/* The [3] explicit tag wrapping the extensions, read from cursor c. */
static int san_next_is_ext_tag(quic_derseq *c, const u8 **val, usz *vlen) {
  u8 tag;
  return quic_derseq_next(c, &tag, val, vlen) && tag == X509_EXTENSIONS_TAG;
}

/* RFC 5280 4.1.2.9. Reach the extensions SEQUENCE value inside [3]. */
static int san_reach_extensions(
    const u8 *tbs, usz tbs_len, const u8 **ext, usz *elen) {
  quic_derseq c;
  const u8   *val;
  usz         vlen;
  if (!san_at_extensions(tbs, tbs_len, &c)) return 0;
  if (!san_next_is_ext_tag(&c, &val, &vlen)) return 0;
  return san_unwrap_seq(val, vlen, ext, elen);
}

/* RFC 5280 4.1.2.9. extnID of one Extension equals the wanted OID. */
static int san_ext_id_is(const u8 *e, usz e_len, const u8 *oid, usz oid_len) {
  quic_derseq f;
  u8          tag;
  const u8   *id;
  usz         id_len;
  quic_derseq_init(&f, e, e_len);
  if (!quic_derseq_next(&f, &tag, &id, &id_len)) return 0;
  return tag == QUIC_DER_OID && quic_der_oid_equal(id, id_len, oid, oid_len);
}

/* RFC 5280 4.1.2.9. The extnValue OCTET STRING of one Extension. */
static int san_ext_value(const u8 *e, usz e_len, const u8 **val, usz *val_len) {
  quic_derseq f;
  u8          tag;
  const u8   *o;
  usz         o_len;
  quic_derseq_init(&f, e, e_len);
  while (quic_derseq_next(&f, &tag, &o, &o_len))
    if (tag == QUIC_DER_OCTET_STRING) {
      *val     = o;
      *val_len = o_len;
      return 1;
    }
  return 0;
}

/* RFC 5280 4.1.2.9. Find the extnValue OCTET STRING of subjectAltName. */
static int find_ext_san(const u8 *ext, usz elen, const u8 **val, usz *val_len) {
  quic_derseq exts;
  u8          tag;
  const u8   *e;
  usz         e_len;
  quic_derseq_init(&exts, ext, elen);
  while (quic_derseq_next(&exts, &tag, &e, &e_len))
    if (san_ext_id_is(e, e_len, oid_san, sizeof(oid_san)))
      return san_ext_value(e, e_len, val, val_len);
  return 0;
}

/* RFC 5280 4.1.2.9. The subjectAltName extnValue OCTET STRING. */
static int find_san(const u8 *tbs, usz tbs_len, const u8 **val, usz *val_len) {
  const u8 *ext;
  usz       elen;
  if (!san_reach_extensions(tbs, tbs_len, &ext, &elen)) return 0;
  return find_ext_san(ext, elen, val, val_len);
}

/* 1 if the two byte spans of equal length differ nowhere. */
static int san_bytes_eq(const u8 *a, const u8 *b, usz n) {
  usz diff = 0;
  for (usz i = 0; i < n; i++) diff |= (usz)(a[i] ^ b[i]);
  return diff == 0;
}

/* Byte-equal hostname comparison (DNS labels are ASCII; no case folding). */
static int dns_eq(const u8 *a, usz alen, const u8 *b, usz blen) {
  return alen == blen && san_bytes_eq(a, b, alen);
}

/* Offset of the first '.' in name, or len if none. */
static usz first_dot(const u8 *name, usz len) {
  usz i = 0;
  while (i < len && name[i] != '.') i++;
  return i;
}

/* RFC 6125 6.4.3. A SAN entry starts with the "*." wildcard label. */
static int is_wildcard(const u8 *entry, usz elen) {
  return elen >= 2 && entry[0] == '*' && entry[1] == '.';
}

/* RFC 6125 6.4.3. A "*." entry matches host iff the wildcard label covers
 * exactly the host's first label and the remainders are equal. */
static int wildcard_match(const u8 *entry, usz elen, const u8 *host, usz hlen) {
  usz hdot = first_dot(host, hlen);
  if (!is_wildcard(entry, elen) || hdot >= hlen) return 0;
  return dns_eq(entry + 1, elen - 1, host + hdot, hlen - hdot);
}

/* One GeneralName dNSName entry matches the hostname. */
static int entry_matches(const u8 *e, usz elen, const u8 *host, usz hlen) {
  return dns_eq(e, elen, host, hlen) || wildcard_match(e, elen, host, hlen);
}

/* RFC 5280 4.2.1.6. The GeneralNames SEQUENCE value inside the extnValue. */
static int san_names(const u8 *tbs, usz tbs_len, const u8 **names, usz *nlen) {
  const u8 *san;
  usz       san_len;
  if (!find_san(tbs, tbs_len, &san, &san_len)) return 0;
  return san_unwrap_seq(san, san_len, names, nlen);
}

/* A GeneralName is a dNSName that matches the hostname. */
static int dnsname_matches(
    u8 tag, const u8 *e, usz elen, const u8 *host, usz hlen) {
  return tag == SAN_DNSNAME_TAG && entry_matches(e, elen, host, hlen);
}

/* RFC 5280 4.2.1.6. Scan the GeneralNames for a matching dNSName. */
static int names_match(const u8 *gn, usz gn_len, const u8 *host, usz hlen) {
  quic_derseq names;
  u8          tag;
  const u8   *e;
  usz         e_len;
  quic_derseq_init(&names, gn, gn_len);
  while (quic_derseq_next(&names, &tag, &e, &e_len))
    if (dnsname_matches(tag, e, e_len, host, hlen)) return 1;
  return 0;
}

int quic_x509_san_matches(
    const u8 *tbs, usz tbs_len, const u8 *hostname, usz host_len) {
  const u8 *gn;
  usz       gn_len;
  if (!san_names(tbs, tbs_len, &gn, &gn_len)) return 0;
  return names_match(gn, gn_len, hostname, host_len);
}
