#include "crypto/pki/cert/selfcert/tbs.h"

#include "common/bytes/util/bytes.h"
#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/encoding/asn1/der.h"

/* RFC 8410 3. id-Ed25519 OID 1.3.101.112. */
static const u8 oid_ed25519[] = {0x2b, 0x65, 0x70};
/* RFC 5280 A.1. id-at-commonName OID 2.5.4.3. */
static const u8 oid_cn[] = {0x55, 0x04, 0x03};
/* RFC 5280 4.1.2.5.1. Fixed validity window as UTCTime YYMMDDHHMMSSZ. */
static const u8 not_before[] = "200101000000Z";
static const u8 not_after[]  = "300101000000Z";
/* UTF8String CN value. */
static const u8 cn_value[] = "localhost";

/* X.690 append cursor: emit TLVs onto buf, latching ok=0 on overflow. */
typedef struct {
  u8 *buf;
  usz cap;
  usz off;
  int ok;
} selfcert_enc;

/* Append one TLV at the cursor, advancing off. Latches ok=0 on overflow. */
static void put(selfcert_enc *e, u8 tag, quic_span val) {
  quic_obuf o = quic_obuf_of(e->buf + e->off, e->cap - e->off);
  if (e->ok && quic_selfcert_der_tlv(tag, val, &o))
    e->off += o.len;
  else
    e->ok = 0;
}

/* Append pre-encoded TLV bytes verbatim onto the cursor. */
static void put_pre(selfcert_enc *e, quic_span tlv) {
  if (e->ok && quic_put_bytes(quic_mspan_of(e->buf, e->cap), &e->off, quic_span_of(tlv.p, tlv.n))) return;
  e->ok = 0;
}

/* A cursor holding n pre-built value bytes, ok only when n is non-zero. */
static selfcert_enc loaded(u8 *buf, usz n) {
  selfcert_enc e = {buf, n, n, n != 0};
  return e;
}

/* Wrap the cursor's bytes in one TLV of tag into out. 0 length on failure. */
static usz wrap(selfcert_enc *e, u8 tag, quic_obuf *out) {
  if (e->ok && quic_selfcert_der_tlv(tag, quic_span_of(e->buf, e->off), out))
    return out->len;
  return 0;
}

/* RFC 5280 4.1.1.2. AlgorithmIdentifier SEQUENCE { id-Ed25519 } (no params). */
static usz build_alg(quic_obuf *out) {
  u8           oid[16];
  selfcert_enc e = {oid, sizeof(oid), 0, 1};
  put(&e, QUIC_DER_OID, quic_span_of(oid_ed25519, sizeof(oid_ed25519)));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.4. AttributeTypeAndValue SEQUENCE{ id-at-commonName, value }.
 */
static usz build_atv(quic_obuf *out) {
  u8           atv[64];
  selfcert_enc e = {atv, sizeof(atv), 0, 1};
  put(&e, QUIC_DER_OID, quic_span_of(oid_cn, sizeof(oid_cn)));
  put(&e, 0x0c, quic_span_of(cn_value, sizeof(cn_value) - 1)); /* UTF8String */
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.4. RelativeDistinguishedName SET{ AttributeTypeAndValue }. */
static usz build_rdn(quic_obuf *out) {
  u8           atv[64];
  quic_obuf    ao = quic_obuf_of(atv, sizeof(atv));
  selfcert_enc e  = loaded(atv, build_atv(&ao));
  return wrap(&e, QUIC_DER_SET, out);
}

/* RFC 5280 4.1.2.4. Name SEQUENCE{ SET{ SEQUENCE{ id-at-commonName, value }}}.
 */
static usz build_name(quic_obuf *out) {
  u8           rdn[80];
  quic_obuf    ro = quic_obuf_of(rdn, sizeof(rdn));
  selfcert_enc e  = loaded(rdn, build_rdn(&ro));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.5. Validity SEQUENCE { notBefore UTCTime, notAfter UTCTime }.
 */
static usz build_validity(quic_obuf *out) {
  u8           v[48];
  selfcert_enc e = {v, sizeof(v), 0, 1};
  put(&e, 0x17, quic_span_of(not_before, sizeof(not_before) - 1)); /* UTCTime */
  put(&e, 0x17, quic_span_of(not_after, sizeof(not_after) - 1));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 8410 4 / RFC 5280 4.1.2.7. SPKI SEQUENCE{ alg, BIT STRING(0x00||pub) }.
 */
static usz build_spki(const u8 pub[32], quic_obuf *out) {
  u8           bits[33], alg[16], inner[80];
  quic_obuf    ao = quic_obuf_of(alg, sizeof(alg));
  selfcert_enc e  = {inner, sizeof(inner), 0, 1};
  usz          bo = 1;
  bits[0]         = 0x00; /* BIT STRING unused-bits */
  quic_put_bytes(quic_mspan_of(bits, sizeof(bits)), &bo, quic_span_of(pub, 32));
  put_pre(&e, quic_span_of(alg, build_alg(&ao)));
  put(&e, QUIC_DER_BIT_STRING, quic_span_of(bits, bo));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* Emit version, serial, signature AlgID and issuer onto e. */
static void selfcert_tbs_head(selfcert_enc *e, quic_span name) {
  static const u8 version[] = {0xa0, 0x03, 0x02, 0x01, 0x02}; /* [0] v3 */
  static const u8 serial[]  = {0x02, 0x01, 0x01};             /* INTEGER 1 */
  u8              alg[16];
  quic_obuf       ao = quic_obuf_of(alg, sizeof(alg));
  put_pre(e, quic_span_of(version, sizeof(version)));
  put_pre(e, quic_span_of(serial, sizeof(serial)));
  put_pre(e, quic_span_of(alg, build_alg(&ao)));
  put_pre(e, name);
}

int quic_selfcert_tbs(const u8 pub[32], quic_obuf *out) {
  u8           name[80], val[48], spki[96], body[512];
  quic_obuf    no = quic_obuf_of(name, sizeof(name));
  quic_obuf    vo = quic_obuf_of(val, sizeof(val));
  quic_obuf    so = quic_obuf_of(spki, sizeof(spki));
  selfcert_enc e  = {body, sizeof(body), 0, 1};
  usz          nn = build_name(&no);
  selfcert_tbs_head(&e, quic_span_of(name, nn));
  put_pre(&e, quic_span_of(val, build_validity(&vo)));
  put_pre(&e, quic_span_of(name, nn));
  put_pre(&e, quic_span_of(spki, build_spki(pub, &so)));
  out->len = wrap(&e, QUIC_DER_SEQUENCE, out);
  return out->len != 0;
}
