#ifndef QUIC_X509_KEYUSAGE_H
#define QUIC_X509_KEYUSAGE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.3. 1 if the cert may sign other certificates: the
 * keyUsage extension is absent (DER default: unconstrained), or present
 * with the keyCertSign bit set. 0 if keyUsage is present without
 * keyCertSign, or malformed. */
int quic_x509_can_sign_certs(quic_span tbs);

/* RFC 8410 5. 1 if a cert whose SubjectPublicKeyInfo is id-X25519/id-X448
 * may be used for key agreement: keyUsage absent (unconstrained), or
 * present with keyAgreement set. 0 if keyUsage is present without
 * keyAgreement, or malformed. */
int quic_x509_keyagreement_ok(quic_span tbs);

/* RFC 8410 5. 1 if an end-entity cert whose SubjectPublicKeyInfo is
 * id-Ed25519/id-Ed448 may be used to sign: keyUsage absent (unconstrained),
 * or present with digitalSignature and/or nonRepudiation set. 0 if keyUsage
 * is present with neither, or malformed. */
int quic_x509_ed_leaf_sig_ok(quic_span tbs);

/* RFC 8410 5. 1 if a CA cert whose SubjectPublicKeyInfo is
 * id-Ed25519/id-Ed448 has an admissible keyUsage: absent (unconstrained), or
 * present with one or more of digitalSignature, nonRepudiation, keyCertSign,
 * cRLSign set. 0 if keyUsage is present with none of those, or malformed. */
int quic_x509_ed_ca_ok(quic_span tbs);

#endif
