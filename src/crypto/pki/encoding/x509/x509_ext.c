#include "crypto/pki/encoding/x509/x509_impl.h"

static int is_true_boolean(u8 tag, wired_span v);
static int ext_value(wired_span e, wired_span* val);
static int find_in_extensions(wired_span ext, wired_span oid, wired_span* val);
static int ext_id(wired_span e, wired_span* id);
static int id_is_known(wired_span id);
static int ext_is_unknown_critical(wired_span e);
static int scan_unknown_critical(wired_span ext);
static usz count_ext_id(wired_span ext, wired_span oid);
static int ext_repeated(wired_span ext, wired_span e);
static int scan_duplicates(wired_span ext);

/* RFC 5280 4.1.2.9. Reach the extensions SEQUENCE value inside [3]. */
int x509_ext_reach(wired_span tbs, wired_span* ext) {
  derseq     c;
  wired_span wrapped;
  if (!x509_at_extensions(tbs, &c)) {
    return 0;
  }
  if (!derseq_next_tagged(&c, X509_EXTENSIONS_TAG, &wrapped)) {
    return 0;
  }
  return der_seq(wrapped, ext);
}

/* RFC 5280 4.1.2.9. extnID of one Extension equals the wanted OID. */
int x509_ext_id_is(wired_span e, wired_span oid) {
  derseq     f;
  wired_span id;
  derseq_init(&f, e);
  if (!derseq_next_tagged(&f, DER_OID, &id)) {
    return 0;
  }
  return der_oid_equal(id, oid);
}

/* X.690 11.1. A DER BOOLEAN encoding TRUE (single non-zero octet). */
static int is_true_boolean(u8 tag, wired_span v) {
  return tag == X509_TAG_BOOLEAN && v.n == 1 && v.p[0] != 0x00;
}

/* RFC 5280 4.1.2.9. critical of one Extension: the element right after
 * extnID when it is a BOOLEAN, else the X.690 DEFAULT FALSE. */
int x509_ext_is_critical(wired_span e) {
  derseq     f;
  u8         tag;
  wired_span id, v;
  derseq_init(&f, e);
  if (!derseq_next_tagged(&f, DER_OID, &id)) {
    return 0;
  }
  if (!derseq_next(&f, &tag, &v)) {
    return 0;
  }
  return is_true_boolean(tag, v);
}

/* RFC 5280 4.1.2.9. The extnValue OCTET STRING of one Extension (its last
 * element, after extnID and the optional critical BOOLEAN). */
static int ext_value(wired_span e, wired_span* val) {
  derseq     f;
  u8         tag;
  wired_span o;
  derseq_init(&f, e);
  while (derseq_next(&f, &tag, &o)) {
    if (tag == DER_OCTET_STRING) {
      *val = o;
      return 1;
    }
  }
  return 0;
}

/* Scan the extensions SEQUENCE for the wanted extnID. */
static int find_in_extensions(wired_span ext, wired_span oid, wired_span* val) {
  derseq     exts;
  u8         tag;
  wired_span e;
  derseq_init(&exts, ext);
  while (derseq_next(&exts, &tag, &e)) {
    if (x509_ext_id_is(e, oid)) {
      return ext_value(e, val);
    }
  }
  return 0;
}

int x509_find_ext(wired_span tbs, wired_span oid, wired_span* val) {
  wired_span ext;
  if (!x509_ext_reach(tbs, &ext)) {
    return 0;
  }
  return find_in_extensions(ext, oid, val);
}

/* RFC 5280 4.2. extnIDs this SDK understands the semantics of. Any other
 * critical extension must reject the certificate (4.2 "MUST reject"). */
static const u8 oid_bc_[] = {0x55, 0x1d, 0x13}; /* 2.5.29.19 basicConstraints */

static const u8 oid_san_[] = {0x55, 0x1d, 0x11}; /* 2.5.29.17 subjectAltName */

static const u8 oid_ku_[] = {0x55, 0x1d, 0x0f}; /* 2.5.29.15 keyUsage */

static const u8 oid_eku_[] = {0x55, 0x1d, 0x25}; /* 2.5.29.37 extKeyUsage */

static const u8 oid_nc_[] = {0x55, 0x1d, 0x1e}; /* 2.5.29.30 nameConstraints */

static const u8 oid_pc_[] = {0x55, 0x1d, 0x24}; /* 2.5.29.36 policyConstr. */

static const u8 oid_iap_[] = {0x55, 0x1d, 0x36}; /* 2.5.29.54 inhibitAnyPol. */

static const u8 oid_cp_[] = {0x55, 0x1d, 0x20}; /* 2.5.29.32 certPolicies */

static const wired_span known_ext_oids[] = {
    {oid_bc_, sizeof(oid_bc_)},   {oid_san_, sizeof(oid_san_)},
    {oid_ku_, sizeof(oid_ku_)},   {oid_eku_, sizeof(oid_eku_)},
    {oid_nc_, sizeof(oid_nc_)},   {oid_pc_, sizeof(oid_pc_)},
    {oid_iap_, sizeof(oid_iap_)}, {oid_cp_, sizeof(oid_cp_)},
};

/* extnID of one Extension. */
static int ext_id(wired_span e, wired_span* id) {
  derseq f;
  derseq_init(&f, e);
  return derseq_next_tagged(&f, DER_OID, id);
}

/* 1 if id matches one of the known extension OIDs. */
static int id_is_known(wired_span id) {
  for (usz i = 0; i < KNOWN_EXT_OID_COUNT; i++) {
    if (der_oid_equal(id, known_ext_oids[i])) {
      return 1;
    }
  }
  return 0;
}

/* RFC 5280 4.2. One Extension rejects iff it is critical and unrecognized. */
static int ext_is_unknown_critical(wired_span e) {
  wired_span id;
  if (!ext_id(e, &id)) {
    return 1;
  }
  if (!x509_ext_is_critical(e)) {
    return 0;
  }
  return !id_is_known(id);
}

/* Scan the extensions SEQUENCE for any unknown-critical Extension. */
static int scan_unknown_critical(wired_span ext) {
  derseq     exts;
  u8         tag;
  wired_span e;
  derseq_init(&exts, ext);
  while (derseq_next(&exts, &tag, &e)) {
    if (ext_is_unknown_critical(e)) {
      return 1;
    }
  }
  return 0;
}

int x509_has_unknown_critical(wired_span tbs) {
  wired_span ext;
  if (!x509_ext_reach(tbs, &ext)) {
    return 0;
  }
  return scan_unknown_critical(ext);
}

/* Number of Extensions in ext whose extnID equals oid. */
static usz count_ext_id(wired_span ext, wired_span oid) {
  derseq     exts;
  u8         tag;
  wired_span e;
  usz        n = 0;
  derseq_init(&exts, ext);
  while (derseq_next(&exts, &tag, &e)) {
    if (x509_ext_id_is(e, oid)) {
      n++;
    }
  }
  return n;
}

/* RFC 5280 4.2. e's extnID occurs more than once in ext (an unreadable
 * extnID is left to ext_is_unknown_critical, which already rejects it). */
static int ext_repeated(wired_span ext, wired_span e) {
  wired_span id;
  if (!ext_id(e, &id)) {
    return 0;
  }
  return count_ext_id(ext, id) > 1;
}

/* Scan the extensions SEQUENCE for any repeated extnID. Quadratic in the
 * extension count, which the certificate's own byte length bounds. */
static int scan_duplicates(wired_span ext) {
  derseq     exts;
  u8         tag;
  wired_span e;
  derseq_init(&exts, ext);
  while (derseq_next(&exts, &tag, &e)) {
    if (ext_repeated(ext, e)) {
      return 1;
    }
  }
  return 0;
}

int x509_has_duplicate_ext(wired_span tbs) {
  wired_span ext;
  if (!x509_ext_reach(tbs, &ext)) {
    return 0;
  }
  return scan_duplicates(ext);
}
