#ifndef QUIC_P256_ECDHE_H
#define QUIC_P256_ECDHE_H

#include "crypto/asymmetric/ecc/p256/p256_point.h"

/** @file
 * RFC 8446 4.2.8 / SEC1 2.3.3: secp256r1 (P-256) ECDHE key_share support.
 * Builds on the field/point arithmetic in p256_field.h / p256_point.h. */

/** SEC1 2.3.3 uncompressed point encoding: 0x04 || X(32) || Y(32). */
#define QUIC_P256_PUBKEY_LEN 65

/** Generate a P-256 ECDHE private key: a uniformly random scalar in
 * [1, n-1] (FIPS 186-4 B.4.2 rejection sampling; n = quic_p256_n).
 * @param priv receives the 32-byte big-endian scalar
 * @return 1 ok, 0 if the RNG failed. */
int quic_p256_keygen(u8 priv[32]);

/** Encode the public key for private scalar priv as a SEC1 uncompressed
 * point (0x04 || X || Y).
 * @param out receives the 65-byte encoding
 * @param priv the 32-byte big-endian private scalar
 * @return 1 ok, 0 if priv*G is the point at infinity (priv invalid). */
int quic_p256_pubkey_encode(u8 out[QUIC_P256_PUBKEY_LEN], const u8 priv[32]);

/** Decode a SEC1 uncompressed point (0x04 || X || Y) into an ec_point.
 * @param in the 65-byte encoding
 * @param out receives the decoded point
 * @return 1 ok, 0 if the leading byte is not 0x04 or the point is not on the
 * curve. */
int quic_p256_pubkey_decode(const u8 in[QUIC_P256_PUBKEY_LEN], ec_point* out);

/** ECDHE shared secret: out = X(priv * peer_pub), the big-endian X
 * coordinate of the scalar product (RFC 8446 7.4.2 / SEC1 3.3.1).
 * @param out receives the 32-byte big-endian shared secret
 * @param priv the caller's 32-byte big-endian private scalar
 * @param peer_pub the peer's SEC1-encoded public key
 * @return 1 ok, 0 if peer_pub does not decode to a valid curve point. */
int quic_p256_ecdh(
    u8 out[32], const u8 priv[32], const u8 peer_pub[QUIC_P256_PUBKEY_LEN]);

#endif
