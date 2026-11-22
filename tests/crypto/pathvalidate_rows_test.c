#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/pki/cert/p256cert/enc.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "test.h"

/* RFC 5280 certificate-field rows driven through castore_validate_chain.
 * Every certificate is built here at test time from the fields below
 * (X.690 DER via selfcert_der_tlv, which computes every length) and signed
 * with Ed25519 (RFC 8410 3/6; RFC 8032 5.1.6 is deterministic, so the bytes
 * are the same on every run). Each row varies ONE field of an otherwise
 * valid path [leaf, mids..] under the root built by pvr_validate. Where the
 * validator reads the field, a paired row that must fail shows it is read;
 * version and serialNumber are skipped unread, so those rows show
 * acceptance only. Keys are 32-byte seeds filled
 * with pvr_seed_byte(k). */

/* Inside every validity window below (decimal YYYYMMDDHHMMSS). */
#define PVR_NOW 20261101000000ULL
#define PVR_DER_MAX 1024
#define PVR_PATH 4
#define PVR_SPAN(a) wired_span_of(a, sizeof(a))
/* A DER TLV written as a string literal: sizeof counts the trailing NUL. */
#define PVR_LIT(s) wired_span_of((const u8*)(s), sizeof(s) - 1)
/* The same two as brace initializers, for static tables. */
#define PVR_B(a) {a, sizeof(a)}
#define PVR_L(s) {(const u8*)(s), sizeof(s) - 1}
/* Name = SEQUENCE(0x13){ SET(0x11){ SEQUENCE(0x0f){ OID 2.5.4.3 (commonName,
 * 06 03 55 04 03), UTF8String(0x0c) of 8 bytes } } }: 5 + 2 + 8 = 15, + 2 =
 * 17, + 2 = 19. s must be exactly 8 characters. */
#define PVR_CN8(s) \
  PVR_LIT("\x30\x13\x31\x11\x30\x0f\x06\x03\x55\x04\x03\x0c\x08" s)
/* UTCTime (tag 0x17, 13 bytes YYMMDDHHMMSSZ), RFC 5280 4.1.2.5.1. */
#define PVR_UTC(s) PVR_LIT("\x17\x0d" s)

/* AlgorithmIdentifier id-Ed25519: SEQUENCE(5){ OID(3) 1.3.101.112 }, no
 * parameters (RFC 8410 3). */
static const u8 pvr_alg[] = {0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70};
/* version [0] EXPLICIT INTEGER: v2 = 1, v3 = 2 (RFC 5280 4.1.2.1). */
static const u8 pvr_v2[]      = {0xa0, 0x03, 0x02, 0x01, 0x01};
static const u8 pvr_v3[]      = {0xa0, 0x03, 0x02, 0x01, 0x02};
static const u8 pvr_serial1[] = {0x01};

/* Extension OIDs (RFC 5280 4.2.1.x, id-ce = 2.5.29 = 55 1d). */
static const u8 pvr_oid_ku[]    = {0x55, 0x1d, 0x0f};
static const u8 pvr_oid_san[]   = {0x55, 0x1d, 0x11};
static const u8 pvr_oid_bc[]    = {0x55, 0x1d, 0x13};
static const u8 pvr_oid_nc[]    = {0x55, 0x1d, 0x1e};
static const u8 pvr_oid_cp[]    = {0x55, 0x1d, 0x20};
static const u8 pvr_oid_pc[]    = {0x55, 0x1d, 0x24};
static const u8 pvr_oid_eku[]   = {0x55, 0x1d, 0x25};
static const u8 pvr_oid_inhib[] = {0x55, 0x1d, 0x36};
/* 1.2.3.4: no extension this SDK knows. */
static const u8 pvr_oid_unknown[] = {0x2a, 0x03, 0x04};

/* Extension values. */
/* basicConstraints SEQUENCE(3){ BOOLEAN TRUE } -- cA, no pathLen. */
static const u8 pvr_bc_ca[] = {0x30, 0x03, 0x01, 0x01, 0xff};
/* keyUsage BIT STRING(2){ 2 unused bits, 0x04 = bit 5 keyCertSign }. */
static const u8 pvr_ku_certsign[] = {0x03, 0x02, 0x02, 0x04};
/* certificatePolicies SEQUENCE(8){ PolicyInformation SEQUENCE(6){ OID(4)
 * 2.5.29.32.0 anyPolicy } }. */
static const u8 pvr_cp_any[] = {0x30, 0x08, 0x30, 0x06, 0x06,
                                0x04, 0x55, 0x1d, 0x20, 0x00};
/* subjectAltName SEQUENCE(17){ [2] dNSName(15) "mid.pvr.example" }. */
static const u8 pvr_san_mid[] =
    "\x30\x11\x82\x0f"
    "mid.pvr.example";
/* nameConstraints SEQUENCE(17){ permittedSubtrees [0](15){ GeneralSubtree
 * SEQUENCE(13){ [2] dNSName(11) "pvr.example" } } }. */
static const u8 pvr_nc_pvr[] =
    "\x30\x11\xa0\x0f\x30\x0d\x82\x0b"
    "pvr.example";
/* policyConstraints SEQUENCE(3){ [1] inhibitPolicyMapping 5 }. */
static const u8 pvr_pc_inhibit5[] = {0x30, 0x03, 0x81, 0x01, 0x05};
/* extKeyUsage SEQUENCE(10){ OID(8) 1.3.6.1.5.5.7.3.1 id-kp-serverAuth }. */
static const u8 pvr_eku_server[] = {0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
                                    0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
/* inhibitAnyPolicy SkipCerts INTEGER 5. */
static const u8 pvr_inhib5[] = {0x02, 0x01, 0x05};
/* leaf subjectAltName SEQUENCE(18){ [2] dNSName(16) "leaf.pvr.example" }
 * (inside pvr_nc_pvr) and SEQUENCE(20){ [2] dNSName(18) "leaf.other.example"
 * } (outside it). */
static const u8 pvr_san_leaf_in[] =
    "\x30\x12\x82\x10"
    "leaf.pvr.example";
static const u8 pvr_san_leaf_out[] =
    "\x30\x14\x82\x12"
    "leaf.other.example";

/* One certificate's TBS fields. */
typedef struct {
  wired_span version;    /* [0] TLV; n 0 omits it (RFC 5280: v1) */
  wired_span serial;     /* INTEGER contents octets */
  wired_span issuer;     /* Name DER */
  wired_span subject;    /* Name DER */
  wired_span not_before; /* Time TLV */
  wired_span not_after;  /* Time TLV */
  wired_span exts;       /* Extension TLVs back to back; n 0: no [3] */
  u8         key;        /* subject key seed index */
  u8         signer;     /* issuer key seed index */
} pvr_spec;

static u8 pvr_seed_byte(u8 k) { return (u8)(0x21 + 0x10 * k); }

static void pvr_seed(u8 k, u8 seed[ED25519_SEED]) {
  bytes_memset(seed, pvr_seed_byte(k), ED25519_SEED);
}

/* Append tag{a || b} to e. */
static void pvr_put2(p256cert_enc* e, u8 tag, wired_span a, wired_span b) {
  u8           v[PVR_DER_MAX];
  p256cert_enc in = {v, sizeof v, 0, 1};
  p256cert_put_pre(&in, a);
  p256cert_put_pre(&in, b);
  CHECK(in.ok);
  p256cert_put(e, tag, wired_span_of(v, in.off));
}

/* SubjectPublicKeyInfo SEQUENCE{ pvr_alg, BIT STRING{ 0 unused, pub } }. */
static void pvr_put_spki(p256cert_enc* e, u8 key) {
  u8         seed[ED25519_SEED], bits[1 + ED25519_PUBKEY] = {0}, bs[40];
  wired_obuf o = obuf_of(bs, sizeof bs);
  pvr_seed(key, seed);
  CHECK(ed25519_keypair(seed, bits + 1));
  CHECK(selfcert_der_tlv(0x03, PVR_SPAN(bits), &o));
  pvr_put2(e, 0x30, PVR_SPAN(pvr_alg), wired_span_of(bs, o.len));
}

/* extensions [3] EXPLICIT SEQUENCE{ exts }, nothing when there are none. */
static void pvr_put_exts(p256cert_enc* e, wired_span exts) {
  u8         seq[PVR_DER_MAX];
  wired_obuf o = obuf_of(seq, sizeof seq);
  if (exts.n == 0) {
    return;
  }
  CHECK(selfcert_der_tlv(0x30, exts, &o));
  p256cert_put(e, 0xa3, wired_span_of(seq, o.len));
}

/* TBSCertificate SEQUENCE (RFC 5280 4.1) into out. */
static wired_span pvr_tbs(const pvr_spec* c, u8* out) {
  u8           body[PVR_DER_MAX];
  p256cert_enc e = {body, sizeof body, 0, 1};
  wired_obuf   o = obuf_of(out, PVR_DER_MAX);
  p256cert_put_pre(&e, c->version);
  p256cert_put(&e, 0x02, c->serial);
  p256cert_put_pre(&e, PVR_SPAN(pvr_alg));
  p256cert_put_pre(&e, c->issuer);
  pvr_put2(&e, 0x30, c->not_before, c->not_after);
  p256cert_put_pre(&e, c->subject);
  pvr_put_spki(&e, c->key);
  pvr_put_exts(&e, c->exts);
  CHECK(e.ok);
  CHECK(selfcert_der_tlv(0x30, wired_span_of(body, e.off), &o));
  return wired_span_of(out, o.len);
}

/* Certificate SEQUENCE{ tbs, pvr_alg, BIT STRING{ 0 unused, Ed25519 sig over
 * tbs by c->signer } } into out. */
static wired_span pvr_cert(const pvr_spec* c, u8* out) {
  u8           tbs[PVR_DER_MAX], seed[ED25519_SEED], sig[1 + ED25519_SIG] = {0};
  u8           body[PVR_DER_MAX];
  wired_span   t = pvr_tbs(c, tbs);
  p256cert_enc e = {body, sizeof body, 0, 1};
  wired_obuf   o = obuf_of(out, PVR_DER_MAX);
  pvr_seed(c->signer, seed);
  CHECK(ed25519_sign(seed, t.p, t.n, sig + 1));
  p256cert_put_pre(&e, t);
  p256cert_put_pre(&e, PVR_SPAN(pvr_alg));
  p256cert_put(&e, 0x03, PVR_SPAN(sig));
  CHECK(e.ok);
  CHECK(selfcert_der_tlv(0x30, wired_span_of(body, e.off), &o));
  return wired_span_of(out, o.len);
}

/* One Extension SEQUENCE{ extnID, [critical TRUE], OCTET STRING{ val } }. */
typedef struct {
  wired_span oid;
  wired_span val;
  int        critical;
} pvr_ext;

/* Encode exts[0..n) back to back into out. */
static wired_span pvr_exts(const pvr_ext* x, usz n, u8* out) {
  static const u8 crit[] = {0x01, 0x01, 0xff};
  p256cert_enc    e      = {out, PVR_DER_MAX, 0, 1};
  for (usz i = 0; i < n; i++) {
    u8           v[256];
    p256cert_enc in = {v, sizeof v, 0, 1};
    p256cert_put(&in, 0x06, x[i].oid);
    p256cert_put_pre(&in, x[i].critical ? PVR_SPAN(crit) : wired_span_of(0, 0));
    p256cert_put(&in, 0x04, x[i].val);
    CHECK(in.ok);
    p256cert_put(&e, 0x30, wired_span_of(v, in.off));
  }
  CHECK(e.ok);
  return wired_span_of(out, e.off);
}

/* One AttributeTypeAndValue: OID body, string tag, value. */
typedef struct {
  wired_span oid;
  u8         tag;
  wired_span value;
} pvr_atav;

/* Name = SEQUENCE OF one-attribute RDNs SET{ SEQUENCE{ OID, value } }. */
static wired_span pvr_name(const pvr_atav* a, usz n, u8* out) {
  u8           rdns[PVR_DER_MAX];
  p256cert_enc e = {rdns, sizeof rdns, 0, 1};
  wired_obuf   o = obuf_of(out, PVR_DER_MAX);
  for (usz i = 0; i < n; i++) {
    u8           v[128];
    p256cert_enc in = {v, sizeof v, 0, 1};
    u8           atav[128];
    wired_obuf   ao = obuf_of(atav, sizeof atav);
    p256cert_put(&in, 0x06, a[i].oid);
    p256cert_put(&in, a[i].tag, a[i].value);
    CHECK(in.ok);
    CHECK(selfcert_der_tlv(0x30, wired_span_of(v, in.off), &ao));
    p256cert_put(&e, 0x31, wired_span_of(atav, ao.len));
  }
  CHECK(e.ok);
  CHECK(selfcert_der_tlv(0x30, wired_span_of(rdns, e.off), &o));
  return wired_span_of(out, o.len);
}

static const pvr_ext pvr_ca_exts[] = {
    {PVR_B(pvr_oid_bc), PVR_B(pvr_bc_ca), 1},
    {PVR_B(pvr_oid_ku), PVR_B(pvr_ku_certsign), 1},
};

/* A v3 CA (basicConstraints cA and keyUsage keyCertSign, both critical,
 * plus extra) named subject, key key, issued by issuer/signer. */
static pvr_spec pvr_ca(
    wired_span subject, u8 key, wired_span issuer, u8 signer, wired_span ex) {
  pvr_spec c = {
      PVR_SPAN(pvr_v3),
      PVR_SPAN(pvr_serial1),
      issuer,
      subject,
      PVR_UTC("250101000000Z"),
      PVR_UTC("491231235959Z"),
      ex,
      key,
      signer};
  return c;
}

/* The CA extensions block (pvr_ca_exts) followed by more[0..n). */
static wired_span pvr_ca_exts_plus(const pvr_ext* more, usz n, u8* out) {
  pvr_ext all[12];
  usz     k = 0;
  for (usz i = 0; i < 2; i++) {
    all[k++] = pvr_ca_exts[i];
  }
  for (usz i = 0; i < n && k < 12; i++) {
    all[k++] = more[i];
  }
  return pvr_exts(all, k, out);
}

/* A v3 leaf named "PVR Leaf" (key 2, serial 2) issued by issuer/signer. */
static pvr_spec pvr_leaf(wired_span issuer, u8 signer) {
  static const u8 serial2[] = {0x02};
  pvr_spec        c         = {
      PVR_SPAN(pvr_v3),
      PVR_SPAN(serial2),
      issuer,
      PVR_CN8("PVR Leaf"),
      PVR_UTC("250101000000Z"),
      PVR_UTC("491231235959Z"),
      wired_span_of(0, 0),
      2,
      signer};
  return c;
}

/* Validate chain[0..n) (leaf first) under the self-signed root "PVR Root"
 * (key 0) at PVR_NOW. */
static int pvr_validate(const pvr_spec* chain, usz n) {
  u8            der[PVR_PATH][PVR_DER_MAX], root_der[PVR_DER_MAX];
  u8            ext[PVR_DER_MAX];
  wired_span    certs[PVR_PATH];
  castore       s;
  castore_entry roots[1];
  pvr_spec      root = pvr_ca(
      PVR_CN8("PVR Root"), 0, PVR_CN8("PVR Root"), 0,
      pvr_ca_exts_plus(0, 0, ext));
  CHECK(n <= PVR_PATH);
  for (usz i = 0; i < n; i++) {
    certs[i] = pvr_cert(&chain[i], der[i]);
  }
  castore_init(&s, roots, 1);
  CHECK(castore_add(&s, pvr_cert(&root, root_der)) == 1);
  return castore_validate_chain(&s, certs, n, PVR_NOW);
}

/* RFC 5280 4.1.2.1: certificates of any version are accepted -- a leaf
 * without the version field, a v2 and a v3 leaf all validate, the fields
 * after the optional version found either way. The parser skips version
 * unread, so this does not show that an absent version means v1. */
static void test_pvr_version_any(void) {
  const wired_span vers[] = {
      wired_span_of(0, 0), PVR_SPAN(pvr_v2), PVR_SPAN(pvr_v3)};
  for (usz i = 0; i < sizeof vers / sizeof *vers; i++) {
    pvr_spec leaf = pvr_leaf(PVR_CN8("PVR Root"), 0);
    leaf.version  = vers[i];
    CHECK(pvr_validate(&leaf, 1) == 1);
  }
}

/* RFC 5280 4.1.2.4: the MUST attribute types (country,
 * organization, organizational unit, distinguished name qualifier, state,
 * common name, serial number, domainComponent) and the SHOULD ones
 * (locality, title, surname, given name, initials, pseudonym, generation
 * qualifier), one per RDN, as a CA's subject and its leaf's issuer: the
 * path validates; one value changed in the leaf's issuer breaks it. */
static const u8 pvr_oid_c[]   = {0x55, 0x04, 0x06};
static const u8 pvr_oid_o[]   = {0x55, 0x04, 0x0a};
static const u8 pvr_oid_ou[]  = {0x55, 0x04, 0x0b};
static const u8 pvr_oid_dnq[] = {0x55, 0x04, 0x2e};
static const u8 pvr_oid_st[]  = {0x55, 0x04, 0x08};
static const u8 pvr_oid_cn[]  = {0x55, 0x04, 0x03};
static const u8 pvr_oid_sn[]  = {0x55, 0x04, 0x05};
static const u8 pvr_oid_l[]   = {0x55, 0x04, 0x07};
static const u8 pvr_oid_t[]   = {0x55, 0x04, 0x0c};
static const u8 pvr_oid_sur[] = {0x55, 0x04, 0x04};
static const u8 pvr_oid_gn[]  = {0x55, 0x04, 0x2a};
static const u8 pvr_oid_ini[] = {0x55, 0x04, 0x2b};
static const u8 pvr_oid_ps[]  = {0x55, 0x04, 0x41};
static const u8 pvr_oid_gq[]  = {0x55, 0x04, 0x2c};
/* 0.9.2342.19200300.100.1.25: 0*40+9 = 09, 2342 = 92 26, 19200300 =
 * 89 93 f2 2c, 100 = 64, 1 = 01, 25 = 19 (base-128, RFC 4519 2.4). */
static const u8 pvr_oid_dc[] = {0x09, 0x92, 0x26, 0x89, 0x93,
                                0xf2, 0x2c, 0x64, 0x01, 0x19};

/* PrintableString 0x13, UTF8String 0x0c, IA5String 0x16. */
static const pvr_atav pvr_std_name[] = {
    {PVR_B(pvr_oid_c), 0x13, PVR_L("JP")},
    {PVR_B(pvr_oid_o), 0x0c, PVR_L("PVR Org")},
    {PVR_B(pvr_oid_ou), 0x0c, PVR_L("PVR Unit")},
    {PVR_B(pvr_oid_dnq), 0x13, PVR_L("q1")},
    {PVR_B(pvr_oid_st), 0x0c, PVR_L("Tokyo")},
    {PVR_B(pvr_oid_cn), 0x0c, PVR_L("PVR Std")},
    {PVR_B(pvr_oid_sn), 0x13, PVR_L("42")},
    {PVR_B(pvr_oid_dc), 0x16, PVR_L("example")},
    {PVR_B(pvr_oid_l), 0x0c, PVR_L("Chiyoda")},
    {PVR_B(pvr_oid_t), 0x0c, PVR_L("CA")},
    {PVR_B(pvr_oid_sur), 0x0c, PVR_L("Doe")},
    {PVR_B(pvr_oid_gn), 0x0c, PVR_L("Jane")},
    {PVR_B(pvr_oid_ini), 0x0c, PVR_L("J")},
    {PVR_B(pvr_oid_ps), 0x0c, PVR_L("pvr")},
    {PVR_B(pvr_oid_gq), 0x0c, PVR_L("III")},
};

#define PVR_STD_N (sizeof pvr_std_name / sizeof *pvr_std_name)

static void test_pvr_standard_attribute_names(void) {
  u8       name[PVR_DER_MAX], other[PVR_DER_MAX], ext[PVR_DER_MAX];
  pvr_atav alt[PVR_STD_N];
  pvr_spec chain[2];
  chain[1] = pvr_ca(
      pvr_name(pvr_std_name, PVR_STD_N, name), 1, PVR_CN8("PVR Root"), 0,
      pvr_ca_exts_plus(0, 0, ext));
  chain[0] = pvr_leaf(chain[1].subject, 1);
  CHECK(pvr_validate(chain, 2) == 1);
  bytes_memcpy(alt, pvr_std_name, sizeof alt);
  alt[4].value    = PVR_LIT("Osaka");
  chain[0].issuer = pvr_name(alt, PVR_STD_N, other);
  CHECK(pvr_validate(chain, 2) == 0);
}

/* RFC 5280 4.1.2.5.1: UTCTime YY >= 50 is 19YY, YY < 50 is 20YY.
 * now is 2026: notBefore 500101000000Z (1950) is in the past, so the leaf
 * validates (2050 would not yet be valid); notAfter 500101000000Z (1950)
 * has passed, so it does not (2050 would still be valid); notAfter
 * 491231235959Z is 2049 (1949 would have expired). */
static void test_pvr_utctime_two_digit_year(void) {
  static const struct {
    const char* nb;
    const char* na;
    int         want;
  } rows[] = {
      {"\x17\x0d"
       "500101000000Z",
       "\x17\x0d"
       "491231235959Z",
       1},
      {"\x17\x0d"
       "250101000000Z",
       "\x17\x0d"
       "500101000000Z",
       0},
      {"\x17\x0d"
       "250101000000Z",
       "\x17\x0d"
       "491231235959Z",
       1},
  };
  for (usz i = 0; i < sizeof rows / sizeof *rows; i++) {
    pvr_spec leaf   = pvr_leaf(PVR_CN8("PVR Root"), 0);
    leaf.not_before = wired_span_of((const u8*)rows[i].nb, 15);
    leaf.not_after  = wired_span_of((const u8*)rows[i].na, 15);
    CHECK(pvr_validate(&leaf, 1) == rows[i].want);
  }
}

/* RFC 5280 4.2: a CA carrying all eight MUST-recognise
 * extensions (keyUsage and basicConstraints from pvr_ca_exts; certificate
 * policies, subject alternative name, name constraints, policy constraints,
 * extended key usage, inhibitAnyPolicy here), every one critical, issues a
 * valid path. An unrecognised critical extension instead fails it, and a leaf
 * outside the name constraints fails it, so the extensions are processed,
 * not skipped. */
static const pvr_ext pvr_must_exts[] = {
    {PVR_B(pvr_oid_cp), PVR_B(pvr_cp_any), 1},
    {PVR_B(pvr_oid_san), PVR_L(pvr_san_mid), 1},
    {PVR_B(pvr_oid_nc), PVR_L(pvr_nc_pvr), 1},
    {PVR_B(pvr_oid_pc), PVR_B(pvr_pc_inhibit5), 1},
    {PVR_B(pvr_oid_eku), PVR_B(pvr_eku_server), 1},
    {PVR_B(pvr_oid_inhib), PVR_B(pvr_inhib5), 1},
    {PVR_B(pvr_oid_unknown), PVR_B(pvr_inhib5), 1},
};

/* [leaf with SAN san, CA with pvr_must_exts[0..n)]. */
static int pvr_must_path(usz n, wired_span san) {
  u8       ext[PVR_DER_MAX], lext[PVR_DER_MAX];
  pvr_ext  l = {PVR_SPAN(pvr_oid_san), san, 0};
  pvr_spec chain[2];
  chain[1] = pvr_ca(
      PVR_CN8("PVR Mid0"), 1, PVR_CN8("PVR Root"), 0,
      pvr_ca_exts_plus(pvr_must_exts, n, ext));
  chain[0]      = pvr_leaf(chain[1].subject, 1);
  chain[0].exts = pvr_exts(&l, 1, lext);
  return pvr_validate(chain, 2);
}

static void test_pvr_must_recognise_critical_exts(void) {
  CHECK(pvr_must_path(6, PVR_LIT(pvr_san_leaf_in)) == 1);
  CHECK(pvr_must_path(7, PVR_LIT(pvr_san_leaf_in)) == 0);
  CHECK(pvr_must_path(6, PVR_LIT(pvr_san_leaf_out)) == 0);
}

/* [leaf, Mid3, Mid2, Mid1] under the root; Mid1 carries basicConstraints
 * bc (critical) in place of pvr_bc_ca. */
static int pvr_three_mids(wired_span bc) {
  u8       e1[PVR_DER_MAX], e2[PVR_DER_MAX], e3[PVR_DER_MAX];
  pvr_ext  x1[2] = {{PVR_SPAN(pvr_oid_bc), bc, 1}, pvr_ca_exts[1]};
  pvr_spec chain[4];
  chain[3] = pvr_ca(
      PVR_CN8("PVR Mid1"), 1, PVR_CN8("PVR Root"), 0, pvr_exts(x1, 2, e1));
  chain[2] = pvr_ca(
      PVR_CN8("PVR Mid2"), 3, chain[3].subject, 1, pvr_ca_exts_plus(0, 0, e2));
  chain[1] = pvr_ca(
      PVR_CN8("PVR Mid3"), 4, chain[2].subject, 3, pvr_ca_exts_plus(0, 0, e3));
  chain[0] = pvr_leaf(chain[1].subject, 4);
  return pvr_validate(chain, 4);
}

/* RFC 5280 4.2.1.9: with no pathLenConstraint the CA limits no
 * path length -- two more CAs below Mid1 validate. pathLenConstraint 2
 * (exactly the two below it) validates too, and 0 fails, so the count is
 * enforced when present. basicConstraints SEQUENCE(6){ TRUE, INTEGER n }. */
static void test_pvr_no_pathlen_no_limit(void) {
  static const u8 pl2[] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02};
  static const u8 pl0[] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00};
  CHECK(pvr_three_mids(PVR_SPAN(pvr_bc_ca)) == 1);
  CHECK(pvr_three_mids(PVR_SPAN(pl2)) == 1);
  CHECK(pvr_three_mids(PVR_SPAN(pl0)) == 0);
}

/* RFC 5280 Appendix B: an OID at the limits -- 20 arcs, seven of them
 * 2^28-1, 100 octets in dotted form:
 * 1.3.6.1.4.1.268435455.268435455.268435455.268435455.268435455.268435455.
 * 268435455.10.11.12.13.14.1.2 (11 + 7 x 10 + 5 x 3 + 2 x 2 = 100). DER: 1.3
 * = 2b, 6 1 4 1 one byte each, 268435455 = 0x0fffffff = ff ff ff 7f (4 x 7
 * bits), the last seven arcs one byte each -- 5 + 28 + 7 = 40 bytes. The CA
 * asserts it as its only policy and requires an explicit policy
 * (policyConstraints SEQUENCE(3){ [0] requireExplicitPolicy 0 }), so the path
 * validates only when the leaf asserts the same OID: a leaf naming the last
 * arc 3 fails. Each value is certificatePolicies SEQUENCE(44){
 * SEQUENCE(42){ OID(40) } }. */
#define PVR_ARC_MAX 0xff, 0xff, 0xff, 0x7f
#define PVR_LONG_OID_HEAD                                              \
  0x30, 0x2c, 0x30, 0x2a, 0x06, 0x28, 0x2b, 0x06, 0x01, 0x04, 0x01,    \
      PVR_ARC_MAX, PVR_ARC_MAX, PVR_ARC_MAX, PVR_ARC_MAX, PVR_ARC_MAX, \
      PVR_ARC_MAX, PVR_ARC_MAX, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x01

static int pvr_long_oid_path(wired_span leaf_cp) {
  static const u8 cp[]  = {PVR_LONG_OID_HEAD, 0x02};
  static const u8 req[] = {0x30, 0x03, 0x80, 0x01, 0x00};
  const pvr_ext   mx[2] = {
      {PVR_SPAN(pvr_oid_cp), PVR_SPAN(cp), 0},
      {PVR_SPAN(pvr_oid_pc), PVR_SPAN(req), 1}};
  pvr_ext  lx = {PVR_SPAN(pvr_oid_cp), leaf_cp, 0};
  u8       ext[PVR_DER_MAX], lext[PVR_DER_MAX];
  pvr_spec chain[2];
  chain[1] = pvr_ca(
      PVR_CN8("PVR MidP"), 1, PVR_CN8("PVR Root"), 0,
      pvr_ca_exts_plus(mx, 2, ext));
  chain[0]      = pvr_leaf(chain[1].subject, 1);
  chain[0].exts = pvr_exts(&lx, 1, lext);
  return pvr_validate(chain, 2);
}

static void test_pvr_long_oid(void) {
  static const u8 same[]  = {PVR_LONG_OID_HEAD, 0x02};
  static const u8 other[] = {PVR_LONG_OID_HEAD, 0x03};
  CHECK(sizeof same == 46);
  CHECK(pvr_long_oid_path(PVR_SPAN(same)) == 1);
  CHECK(pvr_long_oid_path(PVR_SPAN(other)) == 0);
}

/* RFC 5280 4.1.2.2: zero and negative serialNumber values (two's
 * complement contents: 00 = 0, ff = -1, 80 = -128, ff 7f = -129, each the
 * minimal encoding) are handled -- the leaf validates. */
static void test_pvr_serial_zero_and_negative(void) {
  static const u8  s0[] = {0x00}, s1[] = {0xff}, s2[] = {0x80};
  static const u8  s3[]      = {0xff, 0x7f};
  const wired_span serials[] = {
      PVR_SPAN(s0), PVR_SPAN(s1), PVR_SPAN(s2), PVR_SPAN(s3)};
  for (usz i = 0; i < sizeof serials / sizeof *serials; i++) {
    pvr_spec leaf = pvr_leaf(PVR_CN8("PVR Root"), 0);
    leaf.serial   = serials[i];
    CHECK(pvr_validate(&leaf, 1) == 1);
  }
}

void test_pathvalidate_rows(void) {
  test_pvr_version_any();
  test_pvr_standard_attribute_names();
  test_pvr_utctime_two_digit_year();
  test_pvr_must_recognise_critical_exts();
  test_pvr_no_pathlen_no_limit();
  test_pvr_long_oid();
  test_pvr_serial_zero_and_negative();
}
