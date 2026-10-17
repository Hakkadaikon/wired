[Docs](../README.md) › [Features](README.md) › FIPS 197

# FIPS 197 — Advanced Encryption Standard (AES)

EARS requirement ledger extracted from the spec text
(`tasks/specs/fips197.txt`, not in git). Each requirement carries the test
that demonstrates it; an unchecked box with no test line is an open gap.
Status as of 2026-10.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: 12/15 tested, 3 indirect, 0 untested.**

## §3 Notation and Conventions

- [x] F197-001 (§3.4) The implementation shall copy the 16-byte input array
  into the two-dimensional state array with `s[r,c] = in[r + 4c]`, and shall
  copy the final state back to the output array with the inverse mapping.
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - gap: the mapping is implicit in the vector round-trip, not asserted on
    the internal state layout directly.

## §4 Mathematical Preliminaries

- [~] F197-002 (§4.1, §4.2) The implementation shall add two bytes in
  GF(2^8) by XOR and multiply them by polynomial multiplication reduced
  modulo m(x) = x^8+x^4+x^3+x+1 (XTIMES for multiplication by {02}).
  - evidence: `XTIME` in `src/crypto/symmetric/aead/aes/aes.c` implements the
    modular reduction (`((x << 1) ^ ((x >> 7) * 0x1b))`, the byte form of
    m(x)); `MIX_COLUMNS`/`INV_MIX_COLUMNS`-style multiplication by fixed
    small constants is built from repeated `XTIME`. No dedicated GF(2^8)
    multiplication unit test exists; it is only exercised through the full
    `CIPHER()` known-answer tests.
- [x] F197-003 (§4.3) The implementation shall multiply a word by the fixed
  matrix [{02},{01},{01},{03}] (forward) using GF(2^8) multiplication and
  XOR, as the mathematical basis of MIXCOLUMNS().
  - test: `tests/crypto/aes_test.c` — `test_aes_mix_columns_matrix`

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
- [x] F197-007 (§5.1.3) The implementation shall mix each column of the
  state by multiplying it by the fixed matrix
  [{02},{01},{01},{03}] in MIXCOLUMNS().
  - test: `tests/crypto/aes_test.c` — `test_aes_mix_columns_matrix`
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
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`
  - gap: the Nk=4 (`schedule_word`) and Nk=8 (`aes128_schedule_word256`,
    including the extra SUBWORD at i mod 8 = 4) branches are shown only
    through the cipher output; the Nk=6 branch (AES-192) is not shipped.
- [x] F197-010 (§5.2, Table 5) The implementation shall use the ten fixed
  round constants Rcon[1..10] = {01,02,04,08,10,20,40,80,1b,36} (each
  left-most byte only, low three bytes zero) in KEYEXPANSION().
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`
  - gap: AES-128 consumes all ten constants and AES-256 the first seven;
    no test asserts the table values outside the cipher output.

## §5.3 INVCIPHER() / EQINVCIPHER()

F197-011 through F197-015 (INVCIPHER, INVSHIFTROWS, INVSUBBYTES,
INVMIXCOLUMNS, EQINVCIPHER/KEYEXPANSIONEIC) — moved to "Out of scope"; see
below.

## §6 Implementation Considerations

- [x] F197-016 (§6.1) The implementation shall support at least one of the
  three key lengths (128, 192, or 256 bits).
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`
- [x] F197-017 (§6.2) The implementation shall impose no restriction on an
  appropriately generated cryptographic key beyond its length.
  - test: `tests/crypto/aes_test.c` —
    `test_aes_no_key_restriction_beyond_length`
  - test: `tests/crypto/aes_test.c` —
    `test_aes256_no_key_restriction_beyond_length`
  - evidence: `aes128_init` (`src/crypto/symmetric/aead/aes/aes.c`)
    schedules every key byte unconditionally with no validation branch;
    the test drives the all-zero and all-0xff 16-byte keys (the values a
    weak-key check would most plausibly reject) through init+encrypt and
    confirms both succeed and produce distinct ciphertext.
- [~] F197-018 (§6.5) The implementation shall use AES only in conjunction
  with a FIPS-approved or NIST-recommended mode of operation.
  - evidence: `aes128_encrypt`/`aes256_encrypt`
    (`src/crypto/symmetric/aead/aes/aes.h`) and the AES-NI rounds in
    `src/crypto/symmetric/aead/gcmx86/` are called only from the GCM
    modules (SP 800-38D counter mode, `gcm_*.c`, `gcmx86_ctr.c`) and the
    header-protection mask (`hp.c`, `hp_suite.c`: RFC 9001 5.4.3 AES-ECB
    encryption of one sample), confirmed by grep of `src/`. A negative
    test would only re-assert that call-site enumeration.

## Appendix A/B/C — Key Expansion, Cipher, and Example Vectors

- [x] F197-019 (App. A.1, B, C.1) The implementation shall reproduce the
  Appendix B and Appendix C.1 CIPHER() known-answer vectors for a 128-bit
  key (whose round keys are those of Appendix A.1).
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
- [x] F197-020 (App. A.3, C.3) The implementation shall reproduce the
  Appendix C.3 CIPHER() known-answer vector for a 256-bit key (Nk=8,
  Nr=14).
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`

## Out of scope

Requirements this server SDK deliberately does not implement, excluded from
the coverage denominator:

- (Abstract, §1, §5, Table 3, App. A.2) AES-192 (Nk=6, Nr=12) -- no TLS 1.3
  cipher suite uses it. AES-256 (App. A.3, C.3) is implemented
  (`aes256_*` in `src/crypto/symmetric/aead/aes/aes.h`) and keys QUIC
  packet and header protection under `TLS_AES_256_GCM_SHA384`
  (`tests/crypto/aes_test.c` — `test_aes256_appendix_c3`,
  `tests/transport/hp_suite_test.c` — `test_hp_suite`).
- (§5.3 F197-011, §5.3.1 F197-012, §5.3.2 F197-013, §5.3.3 F197-014,
  §5.3.5 F197-015) INVCIPHER(), EQINVCIPHER(), and all of their component
  transformations (INVSHIFTROWS, INVSUBBYTES, INVMIXCOLUMNS,
  KEYEXPANSIONEIC) — QUIC never decrypts with raw AES. GCM (SP 800-38D)
  uses only the forward cipher in counter mode, and RFC 9001 5.4.3 header
  protection uses AES-ECB *encryption* of the sample on both send and
  receive (there is no header "decryption" operation distinct from
  encryption). This SDK ships no AES decryption primitive at all.
- (§6.3) Parameter Extensions (guidance to implementers about future
  revisions defining new Nk/Nb/Nr values) — forward-looking guidance to
  standards implementers, not a testable requirement of this Standard.
- (§6.4) Implementation Suggestions Regarding Various Platforms, including
  "protecting implementations ... against implementation attacks ...
  should be considered" — the Standard places this outside its own scope;
  the scalar path uses a table S-box (the AES-NI path in `gcmx86` does
  not).
- (App. A.2, C.2) AES-192 key expansion and example vector — AES-192 not
  shipped (see above).
- (Announcement 8) Export-control compliance ("must comply with all
  federal laws") — legal notice, not an implementation rule.
- (Appendix D) Change log (informative) — editorial history of the
  publication, not a normative requirement.
