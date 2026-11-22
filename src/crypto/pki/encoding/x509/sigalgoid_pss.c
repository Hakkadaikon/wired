#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/sigalgoid_impl.h"

/* RFC 4055 3.1: id-mgf1 (1.2.840.113549.1.1.8). */
static const u8 sao_mgf1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                              0x0d, 0x01, 0x01, 0x08};
/* RFC 4055 2.1: id-sha256/384/512 (2.16.840.1.101.3.4.2.1/2/3). */
static const u8 sao_sha256[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                0x03, 0x04, 0x02, 0x01};
static const u8 sao_sha384[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                0x03, 0x04, 0x02, 0x02};
static const u8 sao_sha512[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                0x03, 0x04, 0x02, 0x03};

/* The PSS hashes: OID (9 octets each), X509_HASH_* kind and length, which
 * is also the one accepted saltLength. */
static const struct {
  const u8* oid;
  u8        kind;
  u8        len;
} sao_pss_hashes[] = {
    {sao_sha256, X509_HASH_SHA256, 32},
    {sao_sha384, X509_HASH_SHA384, 48},
    {sao_sha512, X509_HASH_SHA512, 64},
};

static int sao_done(const derseq* c) { return c->off == c->len; }

/* The octets after the cursor. */
static wired_span sao_rest(const derseq* c) {
  return wired_span_of(c->p + c->off, c->len - c->off);
}

/* s is exactly one element tagged tag; v views its value. */
static int sao_only(wired_span s, u8 tag, wired_span* v) {
  derseq c;
  derseq_init(&c, s);
  return derseq_next_tagged(&c, tag, v) && sao_done(&c);
}

/* X.680 31.2.7 EXPLICIT [n]: the next element is tagged tag and wraps
 * exactly one inner-tagged element, whose value v views. */
static int sao_explicit(derseq* c, u8 tag, u8 inner, wired_span* v) {
  wired_span w;
  return derseq_next_tagged(c, tag, &w) && sao_only(w, inner, v);
}

static int sao_next_oid_is(derseq* c, const u8* want, usz n) {
  wired_span oid;
  return derseq_next_tagged(c, DER_OID, &oid) &&
         der_oid_equal(oid, wired_span_of(want, n));
}

/* RFC 4055 2.1: hash parameters are absent or NULL, both accepted. */
static int sao_null_or_absent(wired_span rest) {
  wired_span v;
  if (rest.n == 0) {
    return 1;
  }
  return sao_only(rest, DER_NULL, &v) && v.n == 0;
}

static int sao_hash_find(wired_span oid, usz* idx) {
  for (usz i = 0; i < sizeof(sao_pss_hashes) / sizeof(sao_pss_hashes[0]); i++) {
    if (der_oid_equal(oid, wired_span_of(sao_pss_hashes[i].oid, 9))) {
      *idx = i;
      return 1;
    }
  }
  return 0;
}

/* RFC 4055 2.1 HashAlgorithm (SEQUENCE value): a listed SHA-2 OID. */
static int sao_hash_alg(wired_span alg, usz* idx) {
  derseq     c;
  wired_span oid;
  derseq_init(&c, alg);
  if (!derseq_next_tagged(&c, DER_OID, &oid)) {
    return 0;
  }
  return sao_null_or_absent(sao_rest(&c)) && sao_hash_find(oid, idx);
}

/* The MGF1 hash AlgorithmIdentifier, last in the MaskGenAlgorithm. */
static int sao_mgf_hash(derseq* c, usz* idx) {
  wired_span h;
  return derseq_next_tagged(c, DER_SEQUENCE, &h) && sao_done(c) &&
         sao_hash_alg(h, idx);
}

/* MaskGenAlgorithm (SEQUENCE value): id-mgf1 over the message hash idx. */
static int sao_mgf_body(wired_span v, usz idx) {
  derseq m;
  usz    mi;
  derseq_init(&m, v);
  return sao_next_oid_is(&m, sao_mgf1, sizeof(sao_mgf1)) &&
         sao_mgf_hash(&m, &mi) && mi == idx;
}

/* RFC 4055 3.1 [1] maskGenAlgorithm; required, since its MGF1-SHA-1 default
 * is not accepted. */
static int sao_pss_mgf(derseq* c, usz idx) {
  wired_span v;
  return sao_explicit(c, 0xa1, DER_SEQUENCE, &v) && sao_mgf_body(v, idx);
}

/* [0] hashAlgorithm; required, since its SHA-1 default is not accepted. */
static int sao_pss_hash(derseq* c, usz* idx) {
  wired_span h;
  return sao_explicit(c, 0xa0, DER_SEQUENCE, &h) && sao_hash_alg(h, idx);
}

/* The next element is EXPLICIT [tag] INTEGER want. */
static int sao_tagged_int(derseq* c, u8 tag, u64 want) {
  wired_span v;
  u64        x;
  return sao_explicit(c, tag, DER_INTEGER, &v) && der_uint(v.p, v.n, &x) &&
         x == want;
}

/* [2] saltLength = hLen (required: the default 20 is no SHA-2 length), then
 * nothing: [3] trailerField may only be its DEFAULT 1, which DER omits
 * (X.690 11.5). */
static int sao_pss_tail(derseq* c, usz idx) {
  return sao_tagged_int(c, 0xa2, sao_pss_hashes[idx].len) && sao_done(c);
}

static int sao_pss_body(wired_span seq, usz* idx) {
  derseq c;
  derseq_init(&c, seq);
  return sao_pss_hash(&c, idx) && sao_pss_mgf(&c, *idx) &&
         sao_pss_tail(&c, *idx);
}

int x509_sigalg_pss_params(wired_span params, x509_sigalg* out) {
  wired_span seq;
  usz        i;
  if (!sao_only(params, DER_SEQUENCE, &seq)) {
    return 0;
  }
  if (!sao_pss_body(seq, &i)) {
    return 0;
  }
  *out = (x509_sigalg){X509_SIG_RSA_PSS, sao_pss_hashes[i].kind};
  return 1;
}
