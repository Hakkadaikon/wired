#ifndef CRYPTO_PKI_ENCODING_X509_EC_PUBKEY_IMPL_H
#define CRYPTO_PKI_ENCODING_X509_EC_PUBKEY_IMPL_H

/* Internal to the ec_pubkey*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/asymmetric/ecc/p384/p384_field.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"

int  x509_is_compress_tag(u8 tag);
void x509_p256_sqrt(p256_fe r, const p256_fe a);

extern const p256_fe ecpk_p256_b;

#endif
