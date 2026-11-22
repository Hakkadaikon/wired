#ifndef X509_SIGALGOID_IMPL_H
#define X509_SIGALGOID_IMPL_H

#include "crypto/pki/encoding/x509/sigalgoid.h"

/* RFC 4055 3.1 RSASSA-PSS-params (the octets after id-RSASSA-PSS: exactly
 * one SEQUENCE) under the policy in sigalgoid.h. Returns 1 and fills *out
 * with X509_SIG_RSA_PSS and the hash, 0 for anything else. */
int x509_sigalg_pss_params(wired_span params, x509_sigalg* out);

#endif
