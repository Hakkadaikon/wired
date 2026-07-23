[Docs](README.md) › Test Coverage

# Test Coverage

Per-requirement test coverage now lives as one EARS-notation ledger file per
specification, so an unchecked box with no test reference IS the visible
list of what still needs testing:

- **[Features](features/README.md)** — 42 specs (RFCs, FIPS, NIST SPs, one
  draft), each broken into checkbox requirements with a grep-verified test
  reference (file + function) or an honest gap. **854/1246 requirements
  tested (69%), 155 indirect, 237 untested** — see the per-category tables
  there.
- **[Interop Results](interop.md)** — cross-implementation runs against
  quic-go and webtransport-go via
  [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner).
  This is the only tier that proves wire compatibility: a self-loopback test
  cannot catch a spec misreading shared by both ends.

## The four evidence tiers

1. **Unit tests** — `tests/` (unity build, assertions on) runs on every
   commit and in CI. Round-trips, state machines, boundary values, and
   malformed-input rejection.
2. **Official / golden vectors** — where a spec publishes test vectors, the
   implementation is pinned to them (RFC appendix vectors, NIST KATs, real
   OpenSSL-generated certificate chains).
3. **Fuzzing** — three libFuzzer+ASan harnesses (packet header, QPACK,
   X.509), run nightly in CI.
4. **Interop** — proves wire compatibility against independent client
   implementations; see [Interop Results](interop.md).

Each [feature ledger](features/README.md) cites which of these tiers backs
each requirement directly in its `- test:` / `- evidence:` lines.

---

**Next:** [Features](features/README.md) — per-spec EARS requirement
ledgers. ([all docs](README.md))
