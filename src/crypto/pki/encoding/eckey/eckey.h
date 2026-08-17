#ifndef WIRED_ECKEY_H
#define WIRED_ECKEY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/**
 * @file
 * P-256 private-key extraction from the two DER shapes tools emit:
 * SEC1 ECPrivateKey (RFC 5915 3) and PKCS#8 PrivateKeyInfo (RFC 5958 2)
 * wrapping a SEC1 key. Only the leading version INTEGER and the private
 * key OCTET STRING are examined; parameters and the public key are ignored.
 *
 * Also RFC 8410 7 OneAsymmetricKey encode/decode for Ed25519/X25519: the
 * 32-byte key material is carried as-is (CurvePrivateKey), with no bit
 * clamping applied at this layer -- RFC 7748 5/RFC 8032 5.1.5 clamping is
 * applied by the scalar-multiply and signing primitives themselves
 * (src/tls/handshake/core/tls/x25519.c, src/crypto/asymmetric/ecc/ed25519/
 * ed25519_sign.c) on every use, so the imported bytes must stay unclamped
 * to round-trip identically through re-export.
 */

/**
 * Extract the 32-byte P-256 private scalar from key_der.
 *
 * The outer SEQUENCE's version INTEGER selects the shape: 1 means SEC1
 * (RFC 5915 3), 0 means PKCS#8 (RFC 5958 2) whose privateKey OCTET STRING
 * holds a SEC1 key.
 *
 * @param key_der DER-encoded private key (SEC1 or unencrypted PKCS#8).
 * @param out     receives the 32-byte private scalar.
 * @return 1 on success; 0 on malformed DER, a scalar not exactly 32
 *         bytes, or an unsupported structure/version.
 */
int wired_eckey_p256_priv(wired_span key_der, u8 out[32]);

/**
 * Encode a 32-byte Ed25519 seed as an RFC 8410 7 OneAsymmetricKey DER
 * SEQUENCE: version 0, privateKeyAlgorithm { id-Ed25519 }, privateKey
 * OCTET STRING wrapping the CurvePrivateKey OCTET STRING(seed). No
 * publicKey field or attributes are emitted.
 *
 * @param seed the 32-byte Ed25519 private seed (unclamped, RFC 8032 5.1.5).
 * @param out  receives the encoded DER; out->len is set on success.
 * @return 1 on success; 0 if out's capacity is too small.
 */
int wired_eckey_ed25519_pkcs8_encode(const u8 seed[32], wired_obuf* out);

/**
 * Extract the 32-byte Curve25519 private key from an RFC 8410 7
 * OneAsymmetricKey DER SEQUENCE (Ed25519 or X25519: the privateKeyAlgorithm
 * OID is not inspected, matching wired_eckey_p256_priv's treatment of
 * parameters). The returned bytes are exactly the imported CurvePrivateKey
 * octets, unclamped: X25519 (RFC 7748 5) and Ed25519 (RFC 8032 5.1.5) both
 * apply their clamping internally on every scalar use, not at import time.
 *
 * @param key_der DER-encoded OneAsymmetricKey (unencrypted PKCS#8 shape).
 * @param out     receives the 32-byte private key.
 * @return 1 on success; 0 on malformed DER or a key not exactly 32 bytes.
 */
int wired_eckey_curve25519_priv(wired_span key_der, u8 out[32]);

#endif
