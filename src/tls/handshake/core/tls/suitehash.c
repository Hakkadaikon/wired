#include "tls/handshake/core/tls/suitehash.h"

#include "crypto/symmetric/hash/hash/sha384.h"
#include "tls/handshake/core/tls/cipher.h"

static const tls_hash suitehash_sha256 = {
    SHA256_DIGEST, wired_sha256, hkdf_extract, hkdf_expand_label, hmac_sha256};

static const tls_hash suitehash_sha384 = {
    SHA384_DIGEST, sha384, hkdf_extract_384, hkdf_expand_label_384,
    hmac_sha384};

const tls_hash* tls_hash_of(u16 suite) {
  return suite == TLS_AES_256_GCM_SHA384 ? &suitehash_sha384
                                         : &suitehash_sha256;
}
