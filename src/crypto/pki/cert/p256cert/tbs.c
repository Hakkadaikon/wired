#include "crypto/pki/cert/p256cert/tbs.h"

#include "common/platform/clock/clock.h"
#include "crypto/pki/cert/p256cert/enc.h"
#include "crypto/pki/cert/p256cert/spki.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/x509/validity.h"

/* RFC 5758 3.2. ecdsa-with-SHA256 OID 1.2.840.10045.4.3.2. */
static const u8 oid_ecdsa_sha256[] = {0x2a, 0x86, 0x48, 0xce,
                                      0x3d, 0x04, 0x03, 0x02};
/* RFC 5280 A.1. id-at-commonName OID 2.5.4.3. */
static const u8 pc_oid_cn[] = {0x55, 0x04, 0x03};
/* RFC 5280 4.1.2.5.1. Fixed validity window as UTCTime YYMMDDHHMMSSZ. */
static const u8 pc_not_before[] = "200101000000Z";
static const u8 pc_not_after[]  = "300101000000Z";
static const u8 pc_cn_value[]   = "localhost";
/* RFC 5280 4.2.1.6. id-ce-subjectAltName OID 2.5.29.17. */
static const u8 pc_oid_san[] = {0x55, 0x1d, 0x11};
/* RFC 5280 4.2.1.6. dNSName is [2] IMPLICIT IA5String (context tag 0x82). */
#define PC_SAN_DNSNAME_TAG 0x82
/* RFC 5280 4.2.1.6. iPAddress is [7] IMPLICIT OCTET STRING (context tag
 * 0x87); a 4-byte value is an IPv4 address in network byte order. */
#define PC_SAN_IPADDR_TAG 0x87
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT (context tag 0xa3). */
#define PC_EXTENSIONS_TAG 0xa3

usz quic_p256cert_sigalg(quic_obuf* out) {
  u8                inner[16];
  quic_p256cert_enc e = {inner, sizeof(inner), 0, 1};
  quic_p256cert_put(
      &e, QUIC_DER_OID,
      quic_span_of(oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256)));
  return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.4. AttributeTypeAndValue SEQUENCE{ id-at-commonName, value }.
 */
static usz pc_build_atv(quic_obuf* out) {
  u8                inner[64];
  quic_p256cert_enc e = {inner, sizeof(inner), 0, 1};
  quic_p256cert_put(
      &e, QUIC_DER_OID, quic_span_of(pc_oid_cn, sizeof(pc_oid_cn)));
  quic_p256cert_put(
      &e, 0x0c,
      quic_span_of(pc_cn_value, sizeof(pc_cn_value) - 1)); /* UTF8String */
  return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.4. Name SEQUENCE{ SET{ SEQUENCE{ id-at-commonName, value }}}.
 */
static usz pc_build_name(quic_obuf* out) {
  u8                atv[64], rdn[80];
  quic_obuf         ao = quic_obuf_of(atv, sizeof(atv));
  quic_obuf         ro = quic_obuf_of(rdn, sizeof(rdn));
  quic_p256cert_enc er = quic_p256cert_loaded(atv, pc_build_atv(&ao));
  quic_p256cert_enc es =
      quic_p256cert_loaded(rdn, quic_p256cert_wrap(&er, QUIC_DER_SET, &ro));
  return quic_p256cert_wrap(&es, QUIC_DER_SEQUENCE, out);
}

/* W3C WebTransport serverCertificateHashes rejects any cert whose validity
 * window exceeds 14 days (https://www.w3.org/TR/webtransport/#dom-
 * webtransporthash); anchor notAfter that far past notBefore. */
#define PC_VALIDITY_DAYS 14
#define PC_SECS_PER_DAY 86400ULL
/* A browser checks notBefore against ITS OWN clock; anchoring notBefore at
 * the server's exact "now" fails whenever the client's clock runs behind the
 * server's. Backdate an hour to absorb ordinary skew; the total window stays
 * exactly 14 days. */
#define PC_BACKDATE_SECS 3600ULL

/* notBefore = now_secs - 1h, notAfter = notBefore + 14 days, both formatted
 * as UTCTime (RFC 5280 4.1.2.5.1) into nb_out/na_out[13]. An epoch within
 * the first hour (tests with tiny values) anchors at now_secs unbackdated
 * rather than wrapping. */
static void pc_validity_window(u64 now_secs, u8 nb_out[13], u8 na_out[13]) {
  u64 nb_secs =
      now_secs > PC_BACKDATE_SECS ? now_secs - PC_BACKDATE_SECS : now_secs;
  u64 na_secs = nb_secs + PC_VALIDITY_DAYS * PC_SECS_PER_DAY;
  quic_x509_utctime_encode(quic_clock_epoch_to_ymdhms(nb_secs), nb_out);
  quic_x509_utctime_encode(quic_clock_epoch_to_ymdhms(na_secs), na_out);
}

/* RFC 5280 4.1.2.5. Validity SEQUENCE { notBefore UTCTime, notAfter UTCTime }.
 * now_secs = 0 keeps the fixed 2020-2030 window (tests only); otherwise the
 * window is anchored to now_secs (see pc_validity_window). */
static usz pc_build_validity(u64 now_secs, quic_obuf* out) {
  u8                v[48], nb[13], na[13];
  quic_p256cert_enc e = {v, sizeof(v), 0, 1};
  if (now_secs) {
    pc_validity_window(now_secs, nb, na);
    quic_p256cert_put(&e, 0x17, quic_span_of(nb, sizeof(nb)));
    quic_p256cert_put(&e, 0x17, quic_span_of(na, sizeof(na)));
  } else {
    quic_p256cert_put(
        &e, 0x17, quic_span_of(pc_not_before, sizeof(pc_not_before) - 1));
    quic_p256cert_put(
        &e, 0x17, quic_span_of(pc_not_after, sizeof(pc_not_after) - 1));
  }
  return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1. Emit version, serial, signature AlgID, issuer onto e. */
static void tbs_head(quic_p256cert_enc* e, quic_span name) {
  static const u8 version[] = {0xa0, 0x03, 0x02, 0x01, 0x02}; /* [0] v3 */
  static const u8 serial[]  = {0x02, 0x01, 0x01};             /* INTEGER 1 */
  u8              alg[16];
  quic_obuf       ao = quic_obuf_of(alg, sizeof(alg));
  quic_p256cert_put_pre(e, quic_span_of(version, sizeof(version)));
  quic_p256cert_put_pre(e, quic_span_of(serial, sizeof(serial)));
  quic_p256cert_put_pre(e, quic_span_of(alg, quic_p256cert_sigalg(&ao)));
  quic_p256cert_put_pre(e, name);
}

/* RFC 5280 4.2.1.6. GeneralNames SEQUENCE{ dNSName [2] "localhost",
 * iPAddress [7] san_ipv4 (if given) }. A browser validating a connection to
 * an IP literal checks this entry, not the dNSName one -- omitting it is
 * what breaks WebTransport serverCertificateHashes pinning to a bare IP
 * (draft-ietf-webtrans-http3-15, hostname validation still applies). */
static usz pc_build_gennames(const u8* san_ipv4, quic_obuf* out) {
  u8                inner[48];
  quic_p256cert_enc e = {inner, sizeof(inner), 0, 1};
  quic_p256cert_put(
      &e, PC_SAN_DNSNAME_TAG,
      quic_span_of(pc_cn_value, sizeof(pc_cn_value) - 1));
  if (san_ipv4)
    quic_p256cert_put(&e, PC_SAN_IPADDR_TAG, quic_span_of(san_ipv4, 4));
  return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.9. Extension SEQUENCE{ extnID, extnValue OCTET STRING }.
 * extnValue wraps the GeneralNames; SAN is non-critical (DEFAULT FALSE). */
static usz pc_build_san_ext(const u8* san_ipv4, quic_obuf* out) {
  u8                gn[48], ext[64];
  quic_obuf         go = quic_obuf_of(gn, sizeof(gn));
  quic_p256cert_enc eg =
      quic_p256cert_loaded(gn, pc_build_gennames(san_ipv4, &go));
  quic_p256cert_enc e = {ext, sizeof(ext), 0, 1};
  quic_p256cert_put(
      &e, QUIC_DER_OID, quic_span_of(pc_oid_san, sizeof(pc_oid_san)));
  quic_p256cert_put(&e, QUIC_DER_OCTET_STRING, quic_span_of(eg.buf, eg.off));
  return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.9. extensions [3] EXPLICIT { SEQUENCE OF Extension }. */
static usz pc_build_extensions(const u8* san_ipv4, quic_obuf* out) {
  u8                ext[64], seq[80];
  quic_obuf         eo = quic_obuf_of(ext, sizeof(ext));
  quic_obuf         so = quic_obuf_of(seq, sizeof(seq));
  quic_p256cert_enc ee =
      quic_p256cert_loaded(ext, pc_build_san_ext(san_ipv4, &eo));
  quic_p256cert_enc es = quic_p256cert_loaded(
      seq, quic_p256cert_wrap(&ee, QUIC_DER_SEQUENCE, &so));
  return quic_p256cert_wrap(&es, PC_EXTENSIONS_TAG, out);
}

int quic_p256cert_tbs(
    const u8   x[32],
    const u8   y[32],
    const u8*  san_ipv4,
    u64        now_secs,
    quic_obuf* out) {
  u8                name[80], val[48], spki[128], exts[96], body[512];
  quic_obuf         no = quic_obuf_of(name, sizeof(name));
  quic_obuf         vo = quic_obuf_of(val, sizeof(val));
  quic_obuf         so = quic_obuf_of(spki, sizeof(spki));
  quic_obuf         xo = quic_obuf_of(exts, sizeof(exts));
  usz               nn = pc_build_name(&no);
  quic_p256cert_enc e  = {body, sizeof(body), 0, 1};
  quic_p256cert_spki(x, y, &so);
  tbs_head(&e, quic_span_of(name, nn));
  quic_p256cert_put_pre(
      &e, quic_span_of(val, pc_build_validity(now_secs, &vo)));
  quic_p256cert_put_pre(&e, quic_span_of(name, nn)); /* subject */
  quic_p256cert_put_pre(&e, quic_span_of(spki, so.len));
  quic_p256cert_put_pre(
      &e, quic_span_of(exts, pc_build_extensions(san_ipv4, &xo)));
  out->len = quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
  return out->len != 0;
}
