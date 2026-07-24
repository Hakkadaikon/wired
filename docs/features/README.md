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

Interop results (the only tier that proves wire compatibility with an
independent implementation) are tracked separately: see
**[Interop Results](../interop.md)**.

**Total: 858/1246 requirements tested (69%), 159 indirect, 229 untested.**

## QUIC core

| Spec | Tested | Indirect | Untested |
|---|---|---|---|
| [RFC 9000 — QUIC Transport](rfc9000.md) | 143/190 | 24 | 23 |
| [RFC 9001 — Using TLS to Secure QUIC](rfc9001.md) | 49/68 | 9 | 10 |
| [RFC 9002 — Loss Detection and Congestion Control](rfc9002.md) | 51/67 | 8 | 8 |
| [RFC 8999 — Version-Independent Properties](rfc8999.md) | 12/15 | 3 | 0 |

## QUIC extensions

| Spec | Tested | Indirect | Untested |
|---|---|---|---|
| [RFC 9221 — Unreliable Datagram Extension](rfc9221.md) | 22/27 | 2 | 3 |
| [RFC 9287 — Greasing the QUIC Bit](rfc9287.md) | 6/9 | 3 | 0 |
| [RFC 9368 — Compatible Version Negotiation](rfc9368.md) | 17/21 | 3 | 1 |
| [RFC 9369 — QUIC Version 2](rfc9369.md) | 18/25 | 4 | 3 |
| [RFC 9308 — Applicability (informational)](rfc9308.md) | 2/4 | 1 | 1 |
| [RFC 9312 — Manageability (informational)](rfc9312.md) | 2/4 | 1 | 1 |
| [RFC 8899 — DPLPMTUD](rfc8899.md) | 12/31 | 7 | 12 |

## TLS and PKI

| Spec | Tested | Indirect | Untested |
|---|---|---|---|
| [RFC 8446 — TLS 1.3](rfc8446.md) | 70/105 | 18 | 17 |
| [RFC 5280 — X.509 / PKI](rfc5280.md) | 28/44 | 6 | 10 |
| [RFC 5480 — EC public keys in certificates](rfc5480.md) | 13/20 | 1 | 6 |
| [RFC 5758 — ECDSA / SHA-2 signature OIDs](rfc5758.md) | 6/12 | 1 | 5 |
| [RFC 8410 — Ed25519/X25519 algorithm identifiers](rfc8410.md) | 7/16 | 1 | 8 |
| [RFC 6066 — TLS extensions (SNI)](rfc6066.md) | 7/13 | 3 | 3 |
| [RFC 6125 — Service identity verification](rfc6125.md) | 6/11 | 1 | 4 |
| [RFC 7301 — ALPN](rfc7301.md) | 13/14 | 1 | 0 |
| [RFC 8017 — PKCS #1 (RSA)](rfc8017.md) | 19/22 | 3 | 0 |

## Cryptographic primitives

| Spec | Tested | Indirect | Untested |
|---|---|---|---|
| [RFC 8439 — ChaCha20-Poly1305](rfc8439.md) | 17/21 | 4 | 0 |
| [RFC 7748 — X25519](rfc7748.md) | 11/15 | 1 | 3 |
| [RFC 8032 — Ed25519](rfc8032.md) | 13/17 | 0 | 4 |
| [RFC 6979 — Deterministic ECDSA](rfc6979.md) | 16/21 | 2 | 3 |
| [RFC 5869 — HKDF](rfc5869.md) | 4/8 | 1 | 3 |
| [RFC 6090 — EC arithmetic](rfc6090.md) | 18/22 | 2 | 2 |
| [FIPS 197 — AES](fips197.md) | 7/19 | 4 | 8 |
| [SP 800-38D — GCM](sp800-38d.md) | 14/25 | 5 | 6 |
| [FIPS 186-4 — ECDSA / DSS](fips186-4.md) | 16/23 | 3 | 4 |
| [FIPS 180-4 — SHA-2](fips180-4.md) | 23/25 | 1 | 1 |
| [FIPS 198-1 — HMAC](fips198-1.md) | 7/8 | 0 | 1 |

## HTTP/3 and QPACK

| Spec | Tested | Indirect | Untested |
|---|---|---|---|
| [RFC 9114 — HTTP/3](rfc9114.md) | 57/81 | 9 | 15 |
| [RFC 9110 — HTTP semantics](rfc9110.md) | 22/28 | 3 | 3 |
| [RFC 9204 — QPACK](rfc9204.md) | 31/55 | 12 | 12 |
| [RFC 7541 — HPACK (reused by QPACK)](rfc7541.md) | 15/16 | 1 | 0 |
| [RFC 9218 — Extensible priorities](rfc9218.md) | 11/21 | 1 | 9 |

## WebTransport

| Spec | Tested | Indirect | Untested |
|---|---|---|---|
| [draft-ietf-webtrans-http3-15](draft-webtrans-http3.md) | 44/68 | 3 | 21 |
| [RFC 9220 — Extended CONNECT](rfc9220.md) | 9/11 | 1 | 1 |
| [RFC 9297 — HTTP Datagrams and Capsules](rfc9297.md) | 8/23 | 2 | 13 |

## IP/UDP foundations

| Spec | Tested | Indirect | Untested |
|---|---|---|---|
| [RFC 768 — UDP](rfc768.md) | 3/6 | 1 | 2 |
| [RFC 791 — IPv4](rfc791.md) | 5/10 | 2 | 3 |
| [RFC 1071 — Internet checksum](rfc1071.md) | 4/5 | 1 | 0 |

---

**Next:** [Interop Results](../interop.md) — cross-implementation
compatibility runs. ([all docs](../README.md))
