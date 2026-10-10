# BoringSSL test vectors as a third-party oracle

wired's crypto primitives are checked against BoringSSL's own FileTest
vectors (pinned commit `dd73e69a4e86fa178a4d19033c691e9b42cc1088`), in
addition to the existing RFC / FIPS tests. Expected values come only from the
vector files; nothing is derived from wired's output. Provenance, file list
and skip reasons: `tests/vectors/boringssl/README.md`. Tests:
`tests/crypto/bssl_*_test.c`.

## Results (2026-10-05)

| Primitive | Added | Pass | Fail | Skip | Notes |
|---|---|---|---|---|---|
| AES-128-GCM | 74 | 69 | 0 | 5 | skip: NONCE ≠ 12 bytes (API is 96-bit nonce only) |
| AES-256-GCM | 66 | 64 | 0 | 2 | skip: NONCE ≠ 12 bytes |
| ChaCha20-Poly1305 | 81 | 81 | 0 | 0 | truncated tags must be (and are) rejected |
| X25519 | 527 | 526 | 0 | 1 | 518 Wycheproof + 8 `x25519_test.cc` inline (RFC 7748, small order, 1,000 iterations); skip: 1,000,000-iteration test (`DISABLED_` upstream); low-order / zero shared secret rejected |
| Ed25519 | 514 | 514 | 0 | 0 | keygen from seed, deterministic sign, verify |
| ECDSA P-256 | 85 | 85 | 0 | 0 | verify; `Invalid` cases rejected |
| ECDSA P-384 | 85 | 85 | 0 | 0 | verify; `Invalid` cases rejected |
| ECDSA P-224 / P-521 / secp224k1 | 179 | 0 | 0 | 179 | curve not implemented |
| HMAC-SHA256 | 5 | 5 | 0 | 0 | also a SHA-256 oracle |
| HMAC-SHA384 | 3 | 3 | 0 | 0 | also a SHA-384 oracle |
| HMAC-SHA512 | 3 | 3 | 0 | 0 | also a SHA-512 oracle (one key longer than the block) |
| HMAC-MD5 / SHA1 / SHA224 | 12 | 0 | 0 | 12 | hash not implemented |
| HKDF | 0 | – | – | – | no vectors in the allowed files at the pinned commit (moved to C++ test source) |
| SHA-2 (plain digest) | 0 | – | – | – | same; SHA-256/384/512 covered through HMAC |
| RSA | 0 | – | – | – | no RSA vectors in the allowed files |

No failure was found, so there is no open defect from this oracle. To make
sure an all-pass is not vacuous, one expected value was flipped temporarily
in each of the AES-128-GCM, Ed25519 and ECDSA P-256 (a valid case) vector
sets; each produced exactly one failing case (`aes_128_gcm_tests.txt:4-9`,
`ed25519_tests.txt:19-22`, `ecdsa_verify_tests.txt:649-654`), and the files
were restored.

## Known gaps

- AES-GCM with a non-96-bit nonce is not supported by wired's API; QUIC and
  TLS 1.3 only use 96-bit nonces, so this does not affect the protocol.
