[Docs](../README.md) › Features

# Features — Per-Spec Requirement Ledgers

Each file below is an EARS-notation requirement ledger for one specification
(RFC / FIPS / NIST SP / draft), extracted from the spec text in
`tasks/specs/` (not in git) using test-design and loop-engineering methods.
Every requirement carries either a test reference (grep-verified against
this repo's `tests/`) or an honest gap — so an unchecked box with no test
line IS the list of what still needs testing. Legend and format details:
[`tasks/specs/FORMAT.md`](../../tasks/specs/FORMAT.md) (repo-internal, not
published as a doc page).

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how)
- `[ ]` — not demonstrated by any test yet

**Demonstrated** below means `[x]` + `[~]` combined — every requirement that
has *some* test evidence behind it, direct or indirect. **Tested** is `[x]`
alone (a dedicated test). The gap between the two columns is exactly the
`[~]` count: real coverage, just without a test that exercises that one
requirement in isolation — see each spec file's evidence line for how it's
actually exercised.

Interop results (the only tier that proves wire compatibility with an
independent implementation) are tracked separately: see
**[Interop Results](../interop.md)**.

**Total: 1227/1227 requirements demonstrated (100%) — 1002 directly tested,
225 indirect, 0 untested.**

## QUIC core

| Spec | Demonstrated | Tested | Indirect | Untested |
|---|---|---|---|---|
| [RFC 9000 — QUIC Transport](rfc9000.md) | 190/190 | 156 | 34 | 0 |
| [RFC 9001 — Using TLS to Secure QUIC](rfc9001.md) | 68/68 | 53 | 15 | 0 |
| [RFC 9002 — Loss Detection and Congestion Control](rfc9002.md) | 67/67 | 56 | 11 | 0 |
| [RFC 8999 — Version-Independent Properties](rfc8999.md) | 15/15 | 12 | 3 | 0 |

## QUIC extensions

| Spec | Demonstrated | Tested | Indirect | Untested |
|---|---|---|---|---|
| [RFC 9221 — Unreliable Datagram Extension](rfc9221.md) | 27/27 | 23 | 4 | 0 |
| [RFC 9287 — Greasing the QUIC Bit](rfc9287.md) | 9/9 | 6 | 3 | 0 |
| [RFC 9368 — Compatible Version Negotiation](rfc9368.md) | 21/21 | 18 | 3 | 0 |
| [RFC 9369 — QUIC Version 2](rfc9369.md) | 25/25 | 21 | 4 | 0 |
| [RFC 9308 — Applicability (informational)](rfc9308.md) | 4/4 | 2 | 2 | 0 |
| [RFC 9312 — Manageability (informational)](rfc9312.md) | 4/4 | 2 | 2 | 0 |
| [RFC 8899 — DPLPMTUD](rfc8899.md) | 31/31 | 21 | 10 | 0 |

## TLS and PKI

| Spec | Demonstrated | Tested | Indirect | Untested |
|---|---|---|---|---|
| [RFC 8446 — TLS 1.3](rfc8446.md) | 105/105 | 86 | 19 | 0 |
| [RFC 5280 — X.509 / PKI](rfc5280.md) | 44/44 | 35 | 9 | 0 |
| [RFC 5480 — EC public keys in certificates](rfc5480.md) | 20/20 | 18 | 2 | 0 |
| [RFC 5758 — ECDSA / SHA-2 signature OIDs](rfc5758.md) | 10/10 | 8 | 2 | 0 |
| [RFC 8410 — Ed25519/X25519 algorithm identifiers](rfc8410.md) | 16/16 | 14 | 2 | 0 |
| [RFC 6066 — TLS extensions (SNI)](rfc6066.md) | 13/13 | 10 | 3 | 0 |
| [RFC 6125 — Service identity verification](rfc6125.md) | 11/11 | 9 | 2 | 0 |
| [RFC 7301 — ALPN](rfc7301.md) | 14/14 | 13 | 1 | 0 |
| [RFC 8017 — PKCS #1 (RSA)](rfc8017.md) | 22/22 | 19 | 3 | 0 |

## Cryptographic primitives

| Spec | Demonstrated | Tested | Indirect | Untested |
|---|---|---|---|---|
| [RFC 8439 — ChaCha20-Poly1305](rfc8439.md) | 21/21 | 17 | 4 | 0 |
| [RFC 7748 — X25519](rfc7748.md) | 15/15 | 13 | 2 | 0 |
| [RFC 8032 — Ed25519](rfc8032.md) | 17/17 | 16 | 1 | 0 |
| [RFC 6979 — Deterministic ECDSA](rfc6979.md) | 21/21 | 18 | 3 | 0 |
| [RFC 5869 — HKDF](rfc5869.md) | 8/8 | 7 | 1 | 0 |
| [RFC 6090 — EC arithmetic](rfc6090.md) | 22/22 | 20 | 2 | 0 |
| [FIPS 197 — AES](fips197.md) | 14/14 | 9 | 5 | 0 |
| [SP 800-38D — GCM](sp800-38d.md) | 20/20 | 14 | 6 | 0 |
| [FIPS 186-4 — ECDSA / DSS](fips186-4.md) | 20/20 | 17 | 3 | 0 |
| [FIPS 180-4 — SHA-2](fips180-4.md) | 25/25 | 23 | 2 | 0 |
| [FIPS 198-1 — HMAC](fips198-1.md) | 8/8 | 8 | 0 | 0 |

## HTTP/3 and QPACK

| Spec | Demonstrated | Tested | Indirect | Untested |
|---|---|---|---|---|
| [RFC 9114 — HTTP/3](rfc9114.md) | 81/81 | 70 | 11 | 0 |
| [RFC 9110 — HTTP semantics](rfc9110.md) | 28/28 | 24 | 4 | 0 |
| [RFC 9204 — QPACK](rfc9204.md) | 55/55 | 37 | 18 | 0 |
| [RFC 7541 — HPACK (reused by QPACK)](rfc7541.md) | 16/16 | 15 | 1 | 0 |
| [RFC 9218 — Extensible priorities](rfc9218.md) | 20/20 | 18 | 2 | 0 |

## WebTransport

| Spec | Demonstrated | Tested | Indirect | Untested |
|---|---|---|---|---|
| [draft-ietf-webtrans-http3-15](draft-webtrans-http3.md) | 68/68 | 53 | 15 | 0 |
| [RFC 9220 — Extended CONNECT](rfc9220.md) | 11/11 | 10 | 1 | 0 |
| [RFC 9297 — HTTP Datagrams and Capsules](rfc9297.md) | 22/22 | 16 | 6 | 0 |

## IP/UDP foundations

| Spec | Demonstrated | Tested | Indirect | Untested |
|---|---|---|---|---|
| [RFC 768 — UDP](rfc768.md) | 5/5 | 4 | 1 | 0 |
| [RFC 791 — IPv4](rfc791.md) | 9/9 | 7 | 2 | 0 |
| [RFC 1071 — Internet checksum](rfc1071.md) | 5/5 | 4 | 1 | 0 |

---

**Next:** [Interop Results](../interop.md) — cross-implementation
compatibility runs. ([all docs](../README.md))
