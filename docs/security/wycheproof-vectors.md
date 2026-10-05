# Wycheproof vectors: results

Project Wycheproof attack vectors (C2SP/wycheproof `testvectors_v1/`, pinned at
`3fa63dd0344abb611f1fb1d77e119938603ea230`) run as a third-party oracle beside
the RFC / FIPS tests and the BoringSSL vectors. Provenance, the judgement rules
and the skip list are in `tests/vectors/wycheproof/README.md`.

Judgement follows each case's `result`: `valid` must be accepted with the
expected output, `invalid` must be rejected, `acceptable` passes either way and
its outcome is logged (`wyc <file> tcId <n> acceptable: accepted|rejected`).

## Results (2026-10-05)

| Primitive | File(s) | Added | valid OK | invalid rejected | acceptable (accepted / rejected) | Fail | Skip |
|---|---|---:|---:|---:|---|---:|---:|
| AES-GCM | `aes_gcm_test.json` | 316 | 79 | 87 | 0 | 0 | 150 |
| ChaCha20-Poly1305 | `chacha20_poly1305_test.json` | 325 | 256 | 69 | 0 | 0 | 0 |
| X25519 | `x25519_test.json` | 518 | 264 | 0 | 254 (223 / 31) | 0 | 0 |
| Ed25519 | `ed25519_test.json` | 151 | 88 | 63 | 0 | 0 | 0 |
| ECDSA P-256 / SHA-256 | `ecdsa_secp256r1_sha256_test.json` | 484 | 174 | 310 | 0 | 0 | 0 |
| ECDSA P-384 / SHA-384 | `ecdsa_secp384r1_sha384_test.json` | 504 | 194 | 310 | 0 | 0 | 0 |
| ECDSA P-384 / SHA-512 | `ecdsa_secp384r1_sha512_test.json` | 542 | 231 | 311 | 0 | 0 | 0 |
| RSA PKCS#1 v1.5 | `rsa_signature_{2048,3072,4096}_sha{256,384,512}_test.json` (9) | 2330 | 63 | 2253 | 9 (0 / 9) | 0 | 5 |
| RSA-PSS | `rsa_pss_{2048,3072,4096}_sha256_mgf1_32_test.json` (3) | 324 | 189 | 135 | 0 | 0 | 0 |
| HMAC-SHA256 | `hmac_sha256_test.json` | 174 | 66 | 108 | 0 | 0 | 0 |
| HKDF-SHA256 | `hkdf_sha256_test.json` | 86 | 83 | 3 | 0 | 0 | 0 |
| SHA-2 | (no own file; digest of every ECDSA / RSA / HMAC / HKDF case) | — | — | — | — | — | — |
| **Total** | 21 files | **5754** | **1687** | **3649** | **263 (223 / 40)** | **0** | **155** |

Failed tcIds and flags: **none**.

Skips: AES-GCM — AES-192 groups and `valid` cases with a non-96-bit nonce
(wired's AEAD API is 96-bit nonce / 128-bit tag only); RSA PKCS#1 — `valid`
cases with e = 3 (2048_sha256: 2, 2048_sha512: 1, 3072_sha256: 1,
3072_sha512: 1; wired verifies e = 65537 only).

Acceptable outcomes: RSA tcId 8 (MissingNull, DigestInfo without the NULL
parameter) is rejected in all 9 files. X25519 rejects tcIds 32 33 63–86 117
118 154 165 166 (low-order public keys giving an all-zero shared secret, which
RFC 7748 6.1 / RFC 8446 7.4.2 allow to abort on) and accepts the other 223.

## Flag-named tests

The flags LowOrderPublic, NonCanonical, ZeroOrderPublic, SmallPublicKey,
ModifiedTag and ShortMac get a test named after the flag when they appear on
`invalid` cases:

| Test | invalid cases | rejected |
|---|---:|---:|
| `test_wyc_aesgcm_invalid_ModifiedTag_rejected` | 81 | 81 |
| `test_wyc_chacha20poly1305_invalid_ModifiedTag_rejected` | 60 | 60 |
| `test_wyc_hmac_invalid_ModifiedTag_rejected` | 108 | 108 |

The other listed flags never appear on an `invalid` case in the pinned files:
LowOrderPublic, SmallPublicKey and NonCanonicalPublic occur in
`x25519_test.json` only on `acceptable` cases (that file has no `invalid`
case), SmallPublicKey in the RSA PKCS#1 files only on `valid` / `acceptable`
e = 3 cases, and ZeroOrderPublic / ShortMac do not occur in the requested
files. Additional per-flag rejection loops run for flags that do mark
`invalid` cases (Ed25519: SignatureMalleability, CompressedSignature,
InvalidEncoding, TruncatedSignature, SignatureWithGarbage; ECDSA:
BerEncodedSignature, InvalidEncoding, IntegerOverflow, RangeCheck,
MissingZero); all reject every case.
