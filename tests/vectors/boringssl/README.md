# BoringSSL FileTest vectors (third-party oracle)

These files are BoringSSL's own test vectors, used here as an independent
oracle for wired's crypto: every expected value comes from these files, never
from wired's output. Only vector data is vendored; no BoringSSL source code.

## Provenance

- Repository: https://github.com/google/boringssl
- Pinned commit: `dd73e69a4e86fa178a4d19033c691e9b42cc1088`
  (the default branch `main` at the time of import, 2026-10-05; the repository
  no longer has a `master` branch).

| File here | Path at the pinned commit |
|---|---|
| `aes_128_gcm_tests.txt` | `crypto/cipher/test/aes_128_gcm_tests.txt` |
| `aes_256_gcm_tests.txt` | `crypto/cipher/test/aes_256_gcm_tests.txt` |
| `chacha20_poly1305_tests.txt` | `crypto/cipher/test/chacha20_poly1305_tests.txt` |
| `ed25519_tests.txt` | `crypto/curve25519/ed25519_tests.txt` |
| `x25519_test.txt` | `third_party/wycheproof_testvectors/x25519_test.txt` (read by `crypto/curve25519/x25519_test.cc`) |
| `x25519_test_cc_vectors.txt` | inline vectors transcribed from `crypto/curve25519/x25519_test.cc` (each case cites its source lines; the `.cc` itself is not vendored) |
| `ecdsa_verify_tests.txt` | `crypto/fipsmodule/ecdsa/ecdsa_verify_tests.txt` |
| `hmac_tests.txt` | `crypto/hmac/hmac_tests.txt` |

The requested paths `crypto/cipher_extra/test/*`, `crypto/hmac_extra/hmac_tests.txt`
and `crypto/evp/evp_tests.txt` moved upstream; the table gives where the same
files live at the pinned commit.

## How they are used

`scripts/gen_bssl_vectors.py` converts each `.txt` into a `.h` of C arrays
(raw attribute text plus the source line range of every case);
`bssl_vec.h` decodes the values at test time. Regenerate after changing a
vector file:

    python3 scripts/gen_bssl_vectors.py tests/vectors/boringssl/*.txt

Each `tests/crypto/bssl_*_test.c` loops over every case and reports a failing
case as `<file>:<first>-<last>`.

## Skipped (not implemented in wired, or no vectors in the allowed files)

| What | Reason |
|---|---|
| ECDSA P-224, P-521, secp224k1 cases in `ecdsa_verify_tests.txt` | curve not implemented in wired (only P-256 and P-384 verify) |
| HMAC-MD5, HMAC-SHA1, HMAC-SHA224 in `hmac_tests.txt` | hash not implemented in wired |
| HKDF | at the pinned commit `crypto/evp/test/evp_tests.txt` no longer carries HKDF vectors (they moved into `crypto/fipsmodule/hkdf/hkdf_test.cc`, C++ source, not a FileTest file); no allowed file has them |
| SHA-2 (plain digests) | likewise moved out of `evp_tests.txt` into `crypto/digest/digest_test.cc`; SHA-256, SHA-384 and SHA-512 are still exercised through the HMAC vectors |
| RSA | none of the allowed files carries RSA vectors (`crypto/evp/test/rsa_tests.txt` is not in the allowed list) |
| X25519 1,000,000-iteration test | marked `DISABLED_` upstream; the 1,000-iteration case is used |
| AES-GCM cases whose NONCE is not 12 bytes (5 in `aes_128_gcm_tests.txt`, 2 in `aes_256_gcm_tests.txt`) | valid for BoringSSL, but wired's GCM API takes a 96-bit nonce only, so the case cannot be expressed; counted as skip, not as a pass |

Impact of the skipped algorithms on QUIC / WebTransport / MoQT: none of them is
needed by a TLS 1.3 handshake (cipher suites use SHA-256/SHA-384 for HKDF;
MD5 and SHA-1 signatures are forbidden in TLS 1.3 handshakes; P-224 and
secp224k1 are not TLS 1.3 groups or signature schemes; P-521 is optional).
Certificate-chain verification is the exception: a chain signed with P-521
or legacy RSA-SHA-1 cannot be verified by wired.

Per-primitive counts and any remaining failures are summarized in
`docs/security/boringssl-vectors.md`.
