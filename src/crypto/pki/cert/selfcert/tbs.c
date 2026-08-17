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
  u8* buf;
  usz cap;
  usz off;
  int ok;
} selfcert_enc;

/* Append one TLV at the cursor, advancing off. Latches ok=0 on overflow. */
static void put(selfcert_enc* e, u8 tag, wired_span val) {
  wired_obuf o = obuf_of(e->buf + e->off, e->cap - e->off);
  if (e->ok && selfcert_der_tlv(tag, val, &o))
    e->off += o.len;
  else
    e->ok = 0;
}

/* Append pre-encoded TLV bytes verbatim onto the cursor. */
static void put_pre(selfcert_enc* e, wired_span tlv) {
  if (e->ok &&
      bytes_put(
          wired_mspan_of(e->buf, e->cap), &e->off, wired_span_of(tlv.p, tlv.n)))
    return;
  e->ok = 0;
}

/* A cursor holding n pre-built value bytes, ok only when n is non-zero. */
static selfcert_enc loaded(u8* buf, usz n) {
  selfcert_enc e = {buf, n, n, n != 0};
  return e;
}

/* Wrap the cursor's bytes in one TLV of tag into out. 0 length on failure. */
static usz wrap(selfcert_enc* e, u8 tag, wired_obuf* out) {
  if (e->ok && selfcert_der_tlv(tag, wired_span_of(e->buf, e->off), out))
    return out->len;
  return 0;
}

/* RFC 5280 4.1.1.2. AlgorithmIdentifier SEQUENCE { id-Ed25519 } (no params). */
static usz build_alg(wired_obuf* out) {
  u8           oid[16];
  selfcert_enc e = {oid, sizeof(oid), 0, 1};
  put(&e, QUIC_DER_OID, wired_span_of(oid_ed25519, sizeof(oid_ed25519)));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.4. AttributeTypeAndValue SEQUENCE{ id-at-commonName, value }.
 */
static usz build_atv(wired_obuf* out) {
  u8           atv[64];
  selfcert_enc e = {atv, sizeof(atv), 0, 1};
  put(&e, QUIC_DER_OID, wired_span_of(oid_cn, sizeof(oid_cn)));
  put(&e, 0x0c, wired_span_of(cn_value, sizeof(cn_value) - 1)); /* UTF8String */
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.4. RelativeDistinguishedName SET{ AttributeTypeAndValue }. */
static usz build_rdn(wired_obuf* out) {
  u8           atv[64];
  wired_obuf   ao = obuf_of(atv, sizeof(atv));
  selfcert_enc e  = loaded(atv, build_atv(&ao));
  return wrap(&e, QUIC_DER_SET, out);
}

/* RFC 5280 4.1.2.4. Name SEQUENCE{ SET{ SEQUENCE{ id-at-commonName, value }}}.
 */
static usz build_name(wired_obuf* out) {
  u8           rdn[80];
  wired_obuf   ro = obuf_of(rdn, sizeof(rdn));
  selfcert_enc e  = loaded(rdn, build_rdn(&ro));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 5280 4.1.2.5. Validity SEQUENCE { notBefore UTCTime, notAfter UTCTime }.
 */
static usz build_validity(wired_obuf* out) {
  u8           v[48];
  selfcert_enc e = {v, sizeof(v), 0, 1};
  put(&e, 0x17,
      wired_span_of(not_before, sizeof(not_before) - 1)); /* UTCTime */
  put(&e, 0x17, wired_span_of(not_after, sizeof(not_after) - 1));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* RFC 8410 4 / RFC 5280 4.1.2.7. SPKI SEQUENCE{ alg, BIT STRING(0x00||pub) }.
 */
static usz build_spki(const u8 pub[32], wired_obuf* out) {
  u8           bits[33], alg[16], inner[80];
  wired_obuf   ao = obuf_of(alg, sizeof(alg));
  selfcert_enc e  = {inner, sizeof(inner), 0, 1};
  usz          bo = 1;
  bits[0]         = 0x00; /* BIT STRING unused-bits */
  bytes_put(wired_mspan_of(bits, sizeof(bits)), &bo, wired_span_of(pub, 32));
  put_pre(&e, wired_span_of(alg, build_alg(&ao)));
  put(&e, QUIC_DER_BIT_STRING, wired_span_of(bits, bo));
  return wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* Emit version, serial, signature AlgID and issuer onto e. */
static void selfcert_tbs_head(selfcert_enc* e, wired_span name) {
  static const u8 version[] = {0xa0, 0x03, 0x02, 0x01, 0x02}; /* [0] v3 */
  static const u8 serial[]  = {0x02, 0x01, 0x01};             /* INTEGER 1 */
  u8              alg[16];
  wired_obuf      ao = obuf_of(alg, sizeof(alg));
  put_pre(e, wired_span_of(version, sizeof(version)));
  put_pre(e, wired_span_of(serial, sizeof(serial)));
  put_pre(e, wired_span_of(alg, build_alg(&ao)));
  put_pre(e, name);
}

int selfcert_tbs(const u8 pub[32], wired_obuf* out) {
  u8           name[80], val[48], spki[96], body[512];
  wired_obuf   no = obuf_of(name, sizeof(name));
  wired_obuf   vo = obuf_of(val, sizeof(val));
  wired_obuf   so = obuf_of(spki, sizeof(spki));
  selfcert_enc e  = {body, sizeof(body), 0, 1};
  usz          nn = build_name(&no);
  selfcert_tbs_head(&e, wired_span_of(name, nn));
  put_pre(&e, wired_span_of(val, build_validity(&vo)));
  put_pre(&e, wired_span_of(name, nn));
  put_pre(&e, wired_span_of(spki, build_spki(pub, &so)));
  out->len = wrap(&e, QUIC_DER_SEQUENCE, out);
  return out->len != 0;
}
