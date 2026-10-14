# BoringSSL test vectors as a third-party oracle

This page answers one question: does wired's crypto give the same answers as
an established, independent implementation? It is for anyone who wants to
trust (or audit) wired's encryption, signatures and key exchange without
reading the crypto code.

## What a test vector is

A test vector is one recorded input together with the output a correct
implementation must produce: for example a key, a nonce (a number used once
per message) and a plaintext, plus the exact ciphertext and tag that must
come out. A test feeds the input to our code and compares the result with
the recorded output, byte for byte. A vector can also say "this input must
be rejected", such as a forged signature.

## Why vectors from another implementation

wired already checks each primitive against the examples printed in its RFC
or FIPS standard. Those examples are few, and they cover the normal path. A
bug in a rare branch (a carry in big-number math, a length on a boundary, a
malformed signature that should be refused) can pass every RFC example.

BoringSSL is Google's TLS library, used by Chrome and Android. Its developers
collected many cases per algorithm and also bundle the Wycheproof set of known
attack and edge cases (over 500 for X25519 and Ed25519 together with their
own). None of these expected values comes from wired, so a match means
independent sources agree. This is what "third-party oracle" means here: an
outside source of correct answers. We never derive an expected value from
wired's own output.

## BoringSSL's FileTest format

BoringSSL stores its vectors as plain text files that its test runner, called
FileTest, reads. Each case is a block of `NAME: value` (or `NAME = value`)
lines, mostly hex bytes, and a blank line ends the case. One AES-128-GCM case
looks like this:

```text
KEY: 3881e7be1bb3bbcaff20bdb78e5d1b67
NONCE: dcf5b7ae2d7552e2297fcfa9
IN: 0a2714aa7d
AD: c60c64bbf7
CT: 5626f96ecb
TAG: ff4c4f1d92b0abb1d0820833d9eb83c7
```

`IN` is the plaintext, `AD` the extra data that is authenticated but not
encrypted, `CT` the ciphertext and `TAG` the authentication tag.

## Where the files and tests live

The vector files are copied from BoringSSL at the pinned commit
`dd73e69a4e86fa178a4d19033c691e9b42cc1088`. Only the data is copied, no
BoringSSL source code. Provenance, the upstream path of each file and the
skip reasons are in
[`tests/vectors/boringssl/README.md`](../../tests/vectors/boringssl/README.md).
Only a fixed list of BoringSSL vector files was approved for import (the
files in that README's table); "the allowed files" below means that list.

The tests are `tests/crypto/bssl_*_test.c`, one per primitive family. Each
loops over every case in its file and runs as part of `just test`. A failing
case is reported with its line range in the vector file, so you can open the
exact block that disagreed.

## How to read the Results table

Each row is one primitive (one algorithm). The columns mean:

- **Added**: how many cases for this primitive the vector files contain.
- **Pass**: wired produced exactly the expected output, or rejected an input
  the vector marks as invalid.
- **Fail**: wired disagreed with BoringSSL. Any non-zero value here is a bug.
- **Skip**: the case could not be run because wired does not implement that
  algorithm or that input shape. A skip is not counted as a pass.

A dash (–) means none of the vector files imported from the pinned commit
has cases for that primitive, so nothing was run.

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
| ECDSA P-521 | 88 | 88 | 0 | 0 | verify (added 2026-10-10); `Invalid` cases rejected; the raw digest is passed and cut to 521 bits (one 71-byte digest exercises the cut) |
| ECDSA P-224 / secp224k1 | 91 | 0 | 0 | 91 | curve not implemented |
| HMAC-SHA256 | 5 | 5 | 0 | 0 | also a SHA-256 oracle |
| HMAC-SHA384 | 3 | 3 | 0 | 0 | also a SHA-384 oracle |
| HMAC-SHA512 | 3 | 3 | 0 | 0 | also a SHA-512 oracle (one key longer than the block) |
| HMAC-MD5 / SHA1 / SHA224 | 12 | 0 | 0 | 12 | hash not implemented |
| HKDF | 0 | – | – | – | no vectors in the allowed files at the pinned commit (moved to C++ test source) |
| SHA-2 (plain digest) | 0 | – | – | – | same; SHA-256/384/512 covered through HMAC |
| RSA | 0 | – | – | – | no RSA vectors in the allowed files |

What the primitives do, in one line each:

- AES-GCM and ChaCha20-Poly1305 are AEAD ciphers: they encrypt a packet and
  add a tag that detects any change to it. QUIC and TLS 1.3 encrypt every
  packet with one of them.
- X25519 is the key exchange that lets client and server agree on a shared
  secret; the guide walks through it in
  [X25519](https://hakkadaikon.github.io/wired/guide/en/tls/x25519/).
- Ed25519 and ECDSA are signature schemes; the TLS handshake uses them to
  prove and check a server's identity (see
  [Certificates](https://hakkadaikon.github.io/wired/guide/en/tls/certificates/)).
- HMAC is a keyed checksum built on a hash such as
  [SHA-256](https://hakkadaikon.github.io/wired/guide/en/tls/sha256/); HKDF
  derives keys from HMAC.

## Checking that the tests can fail

No case failed, so this oracle found no open defect. An all-pass result is
only meaningful if the test would notice a wrong answer, so we broke things
on purpose and confirmed the tests caught it.

One expected value was flipped temporarily in each of three vector sets:
AES-128-GCM, Ed25519 and ECDSA P-256 (in a valid P-256 case). Each produced
exactly one failing case (`aes_128_gcm_tests.txt:4-9`,
`ed25519_tests.txt:19-22`, `ecdsa_verify_tests.txt:649-654`), and the files
were restored.

For P-521 (2026-10-10) the verifier itself was broken instead. An ECDSA
verifier computes a curve point R from the message and the public key, and
accepts only if R's x-coordinate matches the signature's r value. We removed
that comparison and accepted any R that is not the point at infinity (the
curve's "zero"). 63 of the 88 P-521 cases failed, then the source
was restored.

## Known gaps

Every skip in the table has a reason, and none of them weakens QUIC, HTTP/3,
WebTransport or MoQT. There are two kinds of gap. Algorithms wired does not
implement (P-224, secp224k1, MD5, SHA-1, SHA-224) are not needed by a TLS 1.3
handshake. HKDF, SHA-2 and RSA are implemented and used, but the allowed files
have no FileTest vectors for them, so other tests cover them (see the bullet
below).

- **AES-GCM with a nonce that is not 96 bits (12 bytes).** BoringSSL accepts
  other lengths, but wired's API takes only a 96-bit nonce, so those cases
  cannot be expressed. QUIC and TLS 1.3 always use 96-bit nonces, so the
  protocol never needs the other lengths.
- **ECDSA P-224 and secp224k1.** wired verifies only P-256, P-384 and P-521.
  Neither curve is a TLS 1.3 group or signature scheme.
- **HMAC with MD5, SHA-1 or SHA-224.** wired does not implement these hashes.
  TLS 1.3 cipher suites use SHA-256 or SHA-384, and MD5 and SHA-1
  signatures are forbidden in the TLS 1.3 handshake.
- **HKDF, plain SHA-2 and RSA.** The pinned commit has no FileTest vectors
  for them in the allowed files (HKDF and SHA-2 moved into C++ test source).
  SHA-256, SHA-384 and SHA-512 are still exercised through the HMAC rows;
  HKDF, SHA-2 and RSA keep their own RFC and FIPS tests, and RSA and HKDF
  are checked against Wycheproof instead; see
  [Wycheproof vectors](wycheproof-vectors.md).
- **X25519 1,000,000-iteration test.** BoringSSL itself disables it; the
  1,000-iteration case runs instead.

One real limit follows from the missing algorithms: a certificate chain
signed with legacy RSA-SHA-1 cannot be verified by wired.
