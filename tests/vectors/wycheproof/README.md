# Wycheproof attack vectors (third-party oracle)

Project Wycheproof's test vectors exercise known attacks and edge cases
(malleable signatures, low-order points, non-canonical encodings, modified or
truncated tags, ...). They are used here as an independent oracle for wired's
crypto, beside the RFC / FIPS tests and the BoringSSL vectors
(`tests/vectors/boringssl/`). Every expected value and every accept/reject
decision comes from the JSON's `result` field; nothing is derived from wired.
Only the JSON data is vendored; no Wycheproof code.

## Provenance

- Repository: https://github.com/C2SP/wycheproof
- Pinned commit: `3fa63dd0344abb611f1fb1d77e119938603ea230`
  (`master` at the time of import, 2026-10-05), directory `testvectors_v1/`.

| File | Primitive |
|---|---|
| `aes_gcm_test.json` | AES-GCM |
| `chacha20_poly1305_test.json` | ChaCha20-Poly1305 |
| `x25519_test.json` | X25519 |
| `ed25519_test.json` | Ed25519 (the requested `eddsa_test.json` is named `ed25519_test.json` in `testvectors_v1/`) |
| `ecdsa_secp256r1_sha256_test.json` | ECDSA P-256 / SHA-256 |
| `ecdsa_secp384r1_sha384_test.json` | ECDSA P-384 / SHA-384 |
| `ecdsa_secp384r1_sha512_test.json` | ECDSA P-384 / SHA-512 |
| `ecdsa_secp521r1_sha512_test.json` | ECDSA P-521 / SHA-512 (fetched from the same pinned commit, 2026-10-10) |
| `rsa_signature_{2048,3072,4096}_sha{256,384,512}_test.json` | RSASSA-PKCS1-v1_5 (wired's `rsa_pkcs1_verify`: SHA-256/384/512, e = 65537) |
| `rsa_pss_{2048,3072,4096}_sha256_mgf1_32_test.json` | RSASSA-PSS (wired's `rsa_pss_verify`: SHA-256, MGF1-SHA-256, salt 32 = TLS `rsa_pss_rsae_sha256`) |
| `hkdf_sha256_test.json` | HKDF-SHA256 |
| `hmac_sha256_test.json` | HMAC-SHA256 |

SHA-2 has no file of its own in the requested list; SHA-256/384/512 are
exercised as the message digest of every ECDSA and RSA case (and SHA-256 by
HMAC/HKDF), so a wrong digest shows up as a failing valid signature.

## How they are used

`scripts/gen_wycheproof_vectors.py` turns each JSON into a `.h` of C arrays
(tcId, result, flags, and the group/test fields as raw hex; redundant key
encodings DER/PEM/JWK/ASN are dropped). `wyc_vec.h` reads them. Regenerate:

    python3 scripts/gen_wycheproof_vectors.py tests/vectors/wycheproof/*.json

Judgement per case (`tests/crypto/wyc_*_test.c`): `valid` must be accepted
with the expected output; `invalid` must be rejected (accepting is a
failure); `acceptable` passes either way and its outcome is logged. For the
flags LowOrderPublic, NonCanonical, ZeroOrderPublic, SmallPublicKey,
ModifiedTag and ShortMac, a dedicated test whose name carries the flag checks
that every `invalid` case with that flag is rejected. A failing case prints
`FAIL <file> tcId <n> flags=<flags>`.

## Skipped

| What | Reason |
|---|---|
| AES-192-GCM `valid` cases in `aes_gcm_test.json` | AES-192 not implemented (TLS 1.3 / QUIC use AES-128 and AES-256 only); its `invalid` cases count as rejected by construction (see `docs/security/wycheproof-vectors.md`) |
| AES-GCM / ChaCha20-Poly1305 `valid` cases with a nonce other than 96 bits or a tag other than 128 bits | wired's AEAD API takes a 96-bit nonce and a 128-bit tag only (all TLS 1.3 / QUIC uses: RFC 8446 5.3, RFC 5116, RFC 9001 5.3); such `invalid` cases count as rejected |
| RSA groups whose public exponent is not 65537 | `rsa_pkcs1_verify` / `rsa_pss_verify` accept e = 65537 only, by design |
| Other RSA-PSS parameter sets, RSA-OAEP, other ECDSA curves, HMAC/HKDF with other hashes, plain SHA-2 files | not in the requested file list, or not implemented |

Per-primitive counts and any remaining failures:
`docs/security/wycheproof-vectors.md`.
