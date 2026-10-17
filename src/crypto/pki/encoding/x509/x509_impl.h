#ifndef CRYPTO_PKI_ENCODING_X509_X509_IMPL_H
#define CRYPTO_PKI_ENCODING_X509_X509_IMPL_H

/* Internal to the x509*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/x509.h"

#define X509_VERSION_TAG 0xa0
#define X509_ISSUER_UID_TAG 0xa1
#define X509_SUBJECT_UID_TAG 0xa2
#define X509_EXTENSIONS_TAG 0xa3
#define X509_EXT_SKIP 6

/* X.690 8.2. BOOLEAN universal tag. */
#define X509_TAG_BOOLEAN 0x01

#define KNOWN_EXT_OID_COUNT (sizeof(known_ext_oids) / sizeof(known_ext_oids[0]))

int x509_at_extensions(wired_span tbs, derseq* c);

#endif
