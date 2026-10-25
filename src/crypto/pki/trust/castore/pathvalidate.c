#include "crypto/pki/trust/castore/pathvalidate_impl.h"

static int cert_subject(wired_span cert, wired_span* dn);
static int names_chain(wired_span child, wired_span parent);
static int has_unprocessed_critical(wired_span tbs);
static int tbs_extensions_ok(wired_span tbs);
static int cert_extensions_ok(wired_span cert);
static int cert_can_issue(wired_span cert);
static int cert_spki_oid(wired_span cert, wired_span* tbs, wired_span* oid);
static int is_x25519_family(wired_span oid);
static int is_ed_family(wired_span oid);
static int x25519_family_ok(wired_span tbs, wired_span oid);
static int ed_family_ok(wired_span tbs, wired_span oid, int is_ca);
static int parent_may_issue(wired_span parent);

/* RFC 5280 4.2.1.12. The leaf (certs[0], the end-entity server certificate)
 * must permit id-kp-serverAuth: extKeyUsage absent is unrestricted, present
 * without serverAuth rejects. The only caller of validate_chain in this SDK
 * is server-certificate verification (see pathvalidate.h). */
int castore_leaf_allows_server_auth(wired_span leaf) {
  x509 c;
  if (!x509_parse(leaf, &c)) {
    return 0;
  }
  return x509_eku_allows(
      c.tbs, wired_span_of(x509_oid_server_auth, sizeof(x509_oid_server_auth)));
}

/* RFC 5280 4.1.2.4. View cert's issuer Name (header included). */
int castore_cert_issuer(wired_span cert, wired_span* dn) {
  x509 c;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  return x509_issuer(c.tbs, dn);
}

/* RFC 5280 4.1.2.6. View cert's subject Name (header included). */
static int cert_subject(wired_span cert, wired_span* dn) {
  x509 c;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  return x509_subject(c.tbs, dn);
}

/* RFC 5280 6.1.3 (a)(4) with the 7.1 comparison: certs[i]'s issuer equals
 * certs[i+1]'s subject under RFC 4518 caseIgnoreMatch. */
static int names_chain(wired_span child, wired_span parent) {
  wired_span iss, subj;
  if (!castore_cert_issuer(child, &iss)) {
    return 0;
  }
  if (!cert_subject(parent, &subj)) {
    return 0;
  }
  return x509_dn_equal_ci(iss, subj);
}

/* RFC 5280 6.1: "a certificate is self-issued if the DNs that appear in the
 * subject and issuer fields are identical" -- compared by the 7.1 rules
 * (caseIgnoreMatch), the same as name chaining. Malformed Name fields are not
 * self-issued (fails open into being counted, the strict side). */
int castore_cert_self_issued(wired_span cert) {
  wired_span iss, subj;
  if (!castore_cert_issuer(cert, &iss)) {
    return 0;
  }
  if (!cert_subject(cert, &subj)) {
    return 0;
  }
  return x509_dn_equal_ci(iss, subj);
}

/* RFC 5280 4.2.1.4/4.2.1.10/4.2.1.11: a known critical extension carrying
 * a field this SDK does not process (policy qualifiers, subtree
 * minimum/maximum, inhibitPolicyMapping) must reject the certificate. */
static int (*const unprocessed_critical[])(wired_span) = {
    x509_cp_unprocessed_critical,
    x509_nc_unprocessed_critical,
    x509_pc_unprocessed_critical,
};
#define PV_UNPROCESSED_COUNT \
  (sizeof(unprocessed_critical) / sizeof(unprocessed_critical[0]))

static int has_unprocessed_critical(wired_span tbs) {
  for (usz i = 0; i < PV_UNPROCESSED_COUNT; i++) {
    if (unprocessed_critical[i](tbs)) {
      return 1;
    }
  }
  return 0;
}

/* RFC 5280 4.2. tbs carries no unrecognized critical extension, no known
 * critical one with unprocessed fields, and no extnID more than once ("MUST
 * NOT include more than one instance of a particular extension" -- a second
 * nameConstraints/basicConstraints/... instance would otherwise be silently
 * ignored by x509_find_ext). */
static int tbs_extensions_ok(wired_span tbs) {
  if (x509_has_unknown_critical(tbs)) {
    return 0;
  }
  if (has_unprocessed_critical(tbs)) {
    return 0;
  }
  return !x509_has_duplicate_ext(tbs);
}

static int cert_extensions_ok(wired_span cert) {
  x509 c;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  return tbs_extensions_ok(c.tbs);
}

/* Every certificate in the path (leaf through tail) passes the RFC 5280 4.2
 * extension checks (unknown-critical and duplicate both MUST reject). */
int castore_all_extensions_ok(const wired_span* certs, usz n_certs) {
  for (usz i = 0; i < n_certs; i++) {
    if (!cert_extensions_ok(certs[i])) {
      return 0;
    }
  }
  return 1;
}

/* RFC 5280 4.2.1.3/6.1.4. An issuer cert is a CA and, if keyUsage is
 * present, asserts keyCertSign (absent keyUsage is unconstrained). */
static int cert_can_issue(wired_span cert) {
  x509 c;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  if (!x509_is_ca(c.tbs)) {
    return 0;
  }
  return x509_can_sign_certs(c.tbs);
}

/* View cert's tbs and its SPKI algorithm OID. */
static int cert_spki_oid(wired_span cert, wired_span* tbs, wired_span* oid) {
  x509       c;
  wired_span key;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  if (!x509_public_key(c.tbs, oid, &key)) {
    return 0;
  }
  *tbs = c.tbs;
  return 1;
}

/* RFC 8410 3. oid is id-X25519 or id-X448. */
static int is_x25519_family(wired_span oid) {
  return x509_is_x25519(oid) || x509_is_x448(oid);
}

/* RFC 8410 3. oid is id-Ed25519 or id-Ed448. */
static int is_ed_family(wired_span oid) {
  return x509_is_ed25519(oid) || x509_is_ed448(oid);
}

/* RFC 8410 5. If tbs's SPKI is id-X25519/id-X448, keyUsage (if present) must
 * assert keyAgreement. Any other algorithm is unconstrained by this check. */
static int x25519_family_ok(wired_span tbs, wired_span oid) {
  if (!is_x25519_family(oid)) {
    return 1;
  }
  return x509_keyagreement_ok(tbs);
}

/* RFC 5480 2.1.2. oid is the restricted id-ecDH or id-ecMQV identifier. */
static int is_ecdh_family(wired_span oid) {
  return x509_is_ecdh(oid) || x509_is_ecmqv(oid);
}

/* RFC 5480 2.1.2/3. An id-ecDH/id-ecMQV SPKI must carry ECParameters, and
 * keyUsage (if present) must assert keyAgreement and none of the signing
 * bits. Any other algorithm is unconstrained by this check. */
static int ecdh_family_ok(wired_span tbs, wired_span oid) {
  if (!is_ecdh_family(oid)) {
    return 1;
  }
  return x509_ec_restricted_params_ok(tbs) && x509_ecdh_keyusage_ok(tbs);
}

/* The key-agreement families' SPKI-specific checks (RFC 8410 5, RFC 5480 3).
 */
static int agreement_family_ok(wired_span tbs, wired_span oid) {
  return x25519_family_ok(tbs, oid) && ecdh_family_ok(tbs, oid);
}

/* RFC 8410 5. If tbs's SPKI is id-Ed25519/id-Ed448, keyUsage (if present)
 * must admit the role-appropriate bits: leaf sign bits for an end-entity
 * cert, the wider CA bit set for an issuer. Any other algorithm is
 * unconstrained by this check. */
static int ed_family_ok(wired_span tbs, wired_span oid, int is_ca) {
  if (!is_ed_family(oid)) {
    return 1;
  }
  if (is_ca) {
    return x509_ed_ca_ok(tbs);
  }
  return x509_ed_leaf_sig_ok(tbs);
}

/* RFC 8410 5 / RFC 5480 3. cert's SPKI-specific keyUsage constraint, if its
 * algorithm is id-X25519/X448/Ed25519/Ed448 or id-ecDH/id-ecMQV (which also
 * need ECParameters); unconstrained for any other algorithm
 * (RFC 5280's keyCertSign/EKU checks cover those separately). */
int castore_cert_spki_ku_ok(wired_span cert, int is_ca) {
  wired_span tbs, oid;
  if (!cert_spki_oid(cert, &tbs, &oid)) {
    return 0;
  }
  if (!agreement_family_ok(tbs, oid)) {
    return 0;
  }
  return ed_family_ok(tbs, oid, is_ca);
}

/* RFC 5280 4.2.1.12 / RFC 8446 4.4.2.2: the leaf's key signs the TLS
 * CertificateVerify, so a keyUsage it carries must assert digitalSignature
 * -- a purpose consistent with both keyUsage and serverAuth. An
 * id-X25519/X448 key cannot sign; its keyAgreement rule is
 * castore_cert_spki_ku_ok's. */
int castore_leaf_ku_signs(wired_span leaf) {
  wired_span tbs, oid;
  if (!cert_spki_oid(leaf, &tbs, &oid)) {
    return 0;
  }
  if (is_x25519_family(oid)) {
    return 1;
  }
  return x509_digital_signature_ok(tbs);
}

/* RFC 5280 6.1.4/RFC 8410 5. parent is a CA permitted to sign certificates
 * with an admissible SPKI-specific keyUsage. */
static int parent_may_issue(wired_span parent) {
  if (!cert_can_issue(parent)) {
    return 0;
  }
  return castore_cert_spki_ku_ok(parent, 1);
}

/* RFC 5280 6.1.3/6.1.4. One link: name binding, the parent may issue certs,
 * and the parent signs the child. */
int castore_link_ok(wired_span child, wired_span parent) {
  if (!names_chain(child, parent)) {
    return 0;
  }
  if (!parent_may_issue(parent)) {
    return 0;
  }
  return castore_verify_signed_by(child, parent);
}

/* RFC 5280 6.1.4. Find the registered anchor for issuer name and require it
 * to be a CA permitted to issue certs. */
int castore_find_ca_anchor(const castore* s, wired_span iss, wired_span* root) {
  if (!castore_find_by_subject(s, iss, root)) {
    return 0;
  }
  return cert_can_issue(*root);
}
