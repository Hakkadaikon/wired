[Docs](../README.md) › [Features](README.md) › FIPS 197

# FIPS 197 — Advanced Encryption Standard (AES)

EARS requirement ledger extracted from the spec text
(`tasks/specs/fips197.pdf`, not in git). Each requirement carries the test
that demonstrates it; an unchecked box with no test line is an open gap.
Status as of 2026-07.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: 7/19 tested, 4 indirect, 8 untested.**

## §3 Notation and Conventions

- [x] F197-001 (§3.4) The implementation shall copy the 16-byte input array
  into the two-dimensional state array with `s[r,c] = in[r + 4c]`, and shall
  copy the final state back to the output array with the inverse mapping.
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - gap: the mapping is implicit in the vector round-trip, not asserted on
    the internal state layout directly.

## §4 Mathematical Preliminaries

- [~] F197-002 (§4.2) The implementation shall multiply two bytes in
  GF(2^8) by polynomial multiplication reduced modulo
  m(x) = x^8+x^4+x^3+x+1.
  - evidence: `XTIME` in `src/crypto/symmetric/aead/aes/aes.c` implements the
    modular reduction (`((x << 1) ^ ((x >> 7) * 0x1b))`, the byte form of
    m(x)); `MIX_COLUMNS`/`INV_MIX_COLUMNS`-style multiplication by fixed
    small constants is built from repeated `XTIME`. No dedicated GF(2^8)
    multiplication unit test exists; it is only exercised through the full
    `CIPHER()` known-answer tests.
- [ ] F197-003 (§4.3) The implementation shall multiply a word by the fixed
  matrix [{02},{01},{01},{03}] (forward) using GF(2^8) multiplication and
  XOR, as the mathematical basis of MIXCOLUMNS().

## §5.1 CIPHER()

- [x] F197-004 (§5.1) The implementation shall transform the state through
  an initial ADDROUNDKEY, Nr-1 full rounds (SUBBYTES, SHIFTROWS,
  MIXCOLUMNS, ADDROUNDKEY), and a final round that omits MIXCOLUMNS.
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
- [x] F197-005 (§5.1.1) The implementation shall apply the SBOX
  substitution table (Table 4) independently to each byte of the state in
  SUBBYTES().
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
- [~] F197-006 (§5.1.2) The implementation shall cyclically shift row r of
  the state left by r positions in SHIFTROWS(), leaving row 0 unchanged.
  - evidence: `shift_rows`/`shift_col` in
    `src/crypto/symmetric/aead/aes/aes.c` implement
    `t[4c+r] = s[4*((c+r)%4)+r]`; only exercised end to end via the
    known-answer tests, no isolated SHIFTROWS assertion.
- [~] F197-007 (§5.1.3) The implementation shall mix each column of the
  state by multiplying it by the fixed matrix
  [{02},{01},{01},{03}] in MIXCOLUMNS().
  - evidence: `mix_one`/`mix_columns` in
    `src/crypto/symmetric/aead/aes/aes.c` implement the four output-byte
    equations of Eq. 5.8 directly; only exercised end to end via the
    known-answer tests, no isolated MIXCOLUMNS assertion.
- [x] F197-008 (§5.1.4) The implementation shall combine each round key
  (four words from the key schedule) with the state by XOR in
  ADDROUNDKEY(), invoked once before the first round and once per round
  thereafter.
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`

## §5.2 KEYEXPANSION()

- [x] F197-009 (§5.2) The implementation shall expand the cipher key into
  4*(Nr+1) key-schedule words: the first Nk words are the key itself, and
  each subsequent word w[i] is w[i-Nk] XORed with either
  SUBWORD(ROTWORD(w[i-1])) XOR Rcon[i/Nk] (when i is a multiple of Nk),
  SUBWORD(w[i-1]) (AES-256 only, when i+4 is a multiple of 8), or plain
  w[i-1] otherwise.
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - gap: only the AES-128 branch (`i % 4 == 0`) is implemented or tested
    (`schedule_word` in `src/crypto/symmetric/aead/aes/aes.c`); the
    Nk=6/Nk=8 branches (AES-192/AES-256, including the extra AES-256
    SUBWORD step) do not exist in this SDK. See "Out of scope".
- [x] F197-010 (§5.2, Table 5) The implementation shall use the ten fixed
  round constants Rcon[1..10] = {01,02,04,08,10,20,40,80,1b,36} (each
  left-most byte only, low three bytes zero) in KEYEXPANSION().
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - gap: only the first 10 constants are present, matching the AES-128 path
    that consumes all ten; AES-192/256 use a subset, which is moot since
    those key sizes are unimplemented.

## §5.3 INVCIPHER() / EQINVCIPHER()

- [ ] F197-011 (§5.3) The implementation shall provide INVCIPHER(), the
  inverse of CIPHER(), by executing the inverted transformations
  (INVSHIFTROWS, INVSUBBYTES, ADDROUNDKEY, INVMIXCOLUMNS) in reverse round
  order.
  - gap: no decryption path exists; QUIC packet protection and header
    protection only ever call the forward cipher (GCM uses AES in counter
    mode, and header protection uses AES-ECB *encrypt* of the sample per
    RFC 9001 5.4.3), so `quic_aes128_encrypt` has no decrypt counterpart in
    this SDK. See "Out of scope".
- [ ] F197-012 (§5.3.1) The implementation shall cyclically shift row r of
  the state right by r positions in INVSHIFTROWS().
- [ ] F197-013 (§5.3.2) The implementation shall apply the INVSBOX
  substitution table (Table 6, the inverse of Table 4) independently to
  each byte of the state in INVSUBBYTES().
- [ ] F197-014 (§5.3.3) The implementation shall mix each column of the
  state by multiplying it by the fixed matrix
  [{0e},{09},{0d},{0b}] in INVMIXCOLUMNS().
- [ ] F197-015 (§5.3.5) Where the equivalent inverse cipher is used, the
  implementation shall derive the modified key schedule dw via
  KEYEXPANSIONEIC() and execute EQINVCIPHER() with the inverse
  transformations in the same order as CIPHER()'s forward transformations.

## §6 Implementation Considerations

- [~] F197-016 (§6.1) The implementation shall support at least one of the
  three key lengths (128, 192, or 256 bits).
  - evidence: 128-bit keys are supported
    (`QUIC_AES_BLOCK`/`quic_aes128_init` in
    `src/crypto/symmetric/aead/aes/aes.c`); this satisfies the "at least
    one" requirement. 192- and 256-bit keys are not supported — see "Out of
    scope".
- [ ] F197-017 (§6.2) The implementation shall impose no restriction on an
  appropriately generated cryptographic key beyond its length.
- [ ] F197-018 (§6.5) The implementation shall use AES only in conjunction
  with a FIPS-approved or NIST-recommended mode of operation.
  - gap: true in practice (GCM per SP 800-38D, plus RFC 9001 header
    protection), but no test asserts the negative (that raw unmoded AES is
    unreachable from any public API).

## Appendix A/B/C — Key Expansion, Cipher, and Example Vectors

- [x] F197-019 (App. A.1, B) The implementation shall reproduce the
  Appendix A.1 key-schedule and Appendix B CIPHER() known-answer vector for
  a 128-bit key.
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`

## Out of scope

Requirements this server SDK deliberately does not implement, excluded from
the coverage denominator:

- (Abstract, §1, §5, Table 3, App. A.2, A.3) AES-192 and AES-256
  (Nk=6/Nk=8, Nr=12/14) — this SDK implements only AES-128
  (`quic_aes128`/`QUIC_AES_ROUNDS=10` in
  `src/crypto/symmetric/aead/aes/aes.h`). The TLS cipher-suite layer
  actively rejects `TLS_AES_256_GCM_SHA384`
  (`quic_cipher_supported` in `src/tls/handshake/core/tls/cipher.c` returns
  0 for it, confirmed by `tests/tls/cipher_test.c` —
  `test_cipher_supported`); no AES-192 cipher suite exists in TLS 1.3 at
  all. QUIC packet protection and header protection therefore only ever key
  AES-128.
- (§5.3, §5.3.1–§5.3.5) INVCIPHER(), EQINVCIPHER(), and all of their
  component transformations (INVSHIFTROWS, INVSUBBYTES, INVMIXCOLUMNS,
  KEYEXPANSIONEIC) — QUIC never decrypts with raw AES. GCM (SP 800-38D)
  uses only the forward cipher in counter mode, and RFC 9001 5.4.3 header
  protection uses AES-ECB *encryption* of the sample on both send and
  receive (there is no header "decryption" operation distinct from
  encryption). This SDK ships no AES decryption primitive at all.
- (§6.3) Parameter Extensions (guidance to implementers about future
  revisions defining new Nk/Nb/Nr values) — forward-looking guidance to
  standards implementers, not a testable requirement of this Standard.
- (§6.4) Implementation Suggestions Regarding Various Platforms
  (side-channel/cache-timing hardening suggestions, informative) —
  non-normative implementation advice, not a SHALL requirement.
- (Appendix C) Reference to the NIST CSRC website for additional example
  vectors — a pointer to external resources, not a requirement; the
  Appendix B vector this SDK does implement is covered above (F197-019).
- (Appendix D) Change log (informative) — editorial history of the
  publication, not a normative requirement.
