# Security

> **At a glance** — constant-time tag and token comparison everywhere;
> ECDSA/Ed25519/X25519 inputs validated against the known attack classes
> (zero scalars, low-order points, non-canonical encodings); certificate
> chains anchored, CA-bit checked, DER fully bounds-checked; QUIC
> anti-amplification and two-level flow control enforced in the event loop;
> no malloc, no printf, no libc anywhere. Two things are deliberately left
> to you: certificate time/hostname checks and request-rate limiting.

The security properties `wired` enforces, organized by subsystem. Each item
states a concrete guarantee and, where useful, the RFC clause and the source
that implements it. This is a description of what the code checks — not a threat
model or an operator hardening guide.

## Scope

- **In scope (this SDK enforces it):** cryptographic primitive correctness,
  certificate chain and signature validation, key agreement input validation,
  and QUIC/HTTP3 core resource and parser safety.
- **Out of scope (the caller / upper layer must supply it):** certificate
  validity-time and hostname checks (the SDK provides the APIs but the clock and
  SNI come from the application), HTTP/3 request-rate limiting, and Retry-token
  time-to-live. These are noted below as caller responsibilities.

## Symmetric crypto & AEAD

- AEAD tag comparison is constant-time (XOR-OR accumulation, no early return);
  used for every tag check — `common/bytes/util/ct.h`, `gcm.c`, `chacha/aead.c`.
- Truncated authentication tags are rejected: the tag length is fixed at 16
  bytes and a minimum packet length is enforced before decryption.
- AEAD nonces are unique: the packet number is monotonic per number space and
  the nonce is `IV XOR PN` (RFC 9001 5.3).
- Raw hashes are never used as a MAC; all MACs go through HMAC with correct
  ipad/opad, closing length-extension (RFC 2104 / FIPS 198-1).
- HMAC keys longer than the block size are folded with SHA-256 first
  (FIPS 198-1).
- Poly1305 clamps `r` and uses a one-time key derived at counter 0
  (RFC 8439).

## Signatures & elliptic curves

- ECDSA rejects `r = 0` and `s = 0` and requires both scalars in `[1, n)`,
  closing the "Psychic Signature" class (CVE-2022-21449) — `ecdsa_verify.c`.
- ECDSA signatures the SDK produces are low-S normalized (`s <= n/2`, matching
  BoringSSL / RFC 6979 practice) — `p256sign/sign.c`. Verification accepts
  standard high-S signatures, as RFC/FIPS verification rules require.
- Ed25519 rejects non-canonical scalars (`S >= L`) — `ed25519_sign.c`.
- Public keys used in signature verification are checked to lie on the curve and
  are rejected if they are the point at infinity — `ecdsa_verify.c`,
  `p256_point.c`.
- ECDSA nonces are deterministic via HMAC-DRBG with range-checked candidate
  generation (RFC 6979) — `rfc6979.c`.
- RSA PKCS#1 v1.5 verification builds the expected encoded message and compares
  it in constant time; RSA-PSS follows RFC 8017 9.1.2 with a correct MGF1.

## X25519 key agreement

- The X25519 shared secret is rejected when it is all-zero, which a low-order
  peer point produces (RFC 7748 6.1); this prevents a non-contributory key
  exchange — `x25519.c`.
- The rejection propagates through every ECDHE call site so a low-order peer key
  aborts the handshake instead of deriving keys from a zero secret — the crypto
  stream, endpoint agreement, the server handshake, and the sdrv flight.
- The scalar is clamped per RFC 7748 (clear low 3 bits, set bit 254, clear
  bit 255).
- Field elements reduce fully mod `p = 2^255 - 19`, including the boundary case
  where the internal value equals `p` (it reduces to 0, not to 19) — this is
  what lets a low-order point produce a true all-zero secret.

## Certificate chain & X.509

- Each link in the chain is verified: the child's issuer name equals the
  parent's subject name and the parent's key signs the child; the tail is
  anchored to a registered trust root — `pathvalidate.c`, `chainverify.c`.
- Every issuer (each intermediate parent and the trust-anchor root) must assert
  `basicConstraints cA = TRUE` (RFC 5280 6.1.4); a non-CA certificate cannot be
  used as an issuer to forge downstream certificates — `pathvalidate.c` via
  `quic_x509_is_ca`. The leaf is not required to be a CA.
- A certificate's inner `tbsCertificate.signatureAlgorithm` must equal its outer
  `signatureAlgorithm` OID (RFC 5280 4.1.1.2); a mismatch is rejected as
  malformed — `chainverify.c`.
- The DER parser bounds every length (only `0x81`/`0x82` long forms, nested
  lengths range-checked) so malformed encodings cannot over-read or exhaust the
  stack — `der.c`, `derseq.c`, `derval.c`.
- **Caller responsibility:** certificate validity-time (`quic_x509_validity_ok`)
  and hostname/SAN matching (`quic_x509_san_matches`) are implemented but require
  the current time and the expected hostname from the application; the SDK does
  not call them itself.

## QUIC / HTTP3 / QPACK

- Anti-amplification is enforced in the core event loop: a server does not send
  more than the allowed multiple of received bytes before address validation
  (RFC 9000 8.1) — `antiamp.c`, `evloop.c`.
- Retry tokens and stateless-reset tokens are HMAC-derived and compared in
  constant time — `retrytoken.c`, `sreset.c`.
- Flow control rejects data past MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS with
  the correct transport error — `flow.c`, `stream_flow.c`, `streams.c`.
- QPACK decoding rejects output overflow, guards Huffman/integer decoding
  against overrun, and bounds the dynamic table — `huffman.c`, `integer.c`.
- Version downgrade is detected (chosen version vs. server-reported) and
  connection IDs are generated from the RNG — `version/downgrade.c`, `cidgen.c`.
- varint and frame parsers bound every read against the remaining buffer.
- **Caller responsibility:** HTTP/3 request-rate limiting (Rapid Reset,
  CVE-2023-44487) and Retry-token time-to-live are application-layer concerns;
  the SDK provides the mechanism (RST handling, HMAC integrity) but not the
  policy.

## Freestanding attack surface

- `src/` links no libc: the freestanding `-ffreestanding -nostdlib` build is the
  proof. No `malloc`/`free` (all buffers are fixed-size), no `printf`/`scanf`
  family, no `getenv`/`system`/`exec`, no `signal` handlers, and no libc string
  functions — each verified absent from production sources.

---

**Next:** [Syscalls](syscalls.md) — every kernel call the SDK makes.
([all docs](README.md))
