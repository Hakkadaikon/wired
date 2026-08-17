#ifndef X509_KEYUSAGE_H
#define X509_KEYUSAGE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.3. 1 if the cert may sign other certificates: the
 * keyUsage extension is absent (DER default: unconstrained), or present
 * with the keyCertSign bit set. 0 if keyUsage is present without
 * keyCertSign, or malformed. */
int x509_can_sign_certs(wired_span tbs);

/* RFC 8410 5. 1 if a cert whose SubjectPublicKeyInfo is id-X25519/id-X448
 * may be used for key agreement: keyUsage absent (unconstrained), or
 * present with keyAgreement set. 0 if keyUsage is present without
 * keyAgreement, or malformed. */
int x509_keyagreement_ok(wired_span tbs);

/* RFC 8410 5. 1 if an end-entity cert whose SubjectPublicKeyInfo is
 * id-Ed25519/id-Ed448 may be used to sign: keyUsage absent (unconstrained),
 * or present with digitalSignature and/or nonRepudiation set. 0 if keyUsage
 * is present with neither, or malformed. */
int x509_ed_leaf_sig_ok(wired_span tbs);

/* RFC 8410 5. 1 if a CA cert whose SubjectPublicKeyInfo is
 * id-Ed25519/id-Ed448 has an admissible keyUsage: absent (unconstrained), or
 * present with one or more of digitalSignature, nonRepudiation, keyCertSign,
 * cRLSign set. 0 if keyUsage is present with none of those, or malformed. */
int x509_ed_ca_ok(wired_span tbs);

/* RFC 5480 3. 1 if a cert whose SubjectPublicKeyInfo is id-ecDH/id-ecMQV has
 * an admissible keyUsage: absent (unconstrained), or present with
 * keyAgreement set and none of digitalSignature, nonRepudiation,
 * keyEncipherment, keyCertSign, cRLSign set. 0 if keyUsage is present
 * without keyAgreement, or with any of the forbidden bits, or malformed. */
int x509_ecdh_keyusage_ok(wired_span tbs);

#endif
