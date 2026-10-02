[Docs](README.md) › Security

# Security

> **At a glance** — constant-time tag and token comparison everywhere;
> ECDSA/Ed25519/X25519 inputs validated against known attack classes (zero
> scalars, low-order points, non-canonical encodings); certificate chains
> anchored, CA-bit checked, name-constrained, DER fully bounds-checked; QUIC
> anti-amplification, ECN validation and AEAD limits enforced in the event
> loop; MoQT subscriber authorization is opt-in; no malloc, no printf, no
> libc anywhere. Every claim below is backed by a named test or fuzz
> harness. Two things are deliberately left to you: certificate
> time/hostname checks and request-rate limiting.

The security properties `wired` enforces, organized by subsystem. Each item
states a guarantee, the RFC clause where relevant, and the test(s) that pin
it. This is a description of what the code checks — not a threat model.

## Scope

- **In scope:** cryptographic primitive correctness, certificate chain and
  signature validation, key agreement input validation, and QUIC/HTTP3/
  WebTransport/MoQT core resource and parser safety.
- **Out of scope (caller-supplied):** certificate validity-time and hostname
  checks, HTTP/3 request-rate limiting, Retry-token time-to-live, revocation
  checking, and MoQT subscription authorization policy.

### Audit ledger

`docs/security/feature-gaps.md` lists the rows closed only because the
feature does not exist here (revocation checking, client certificates,
ECH, DSA, ...): adding such a feature re-opens its rows.

`docs/security/vuln-ledger.md` is an 837-row ledger built from CVE
databases, peer-implementation security advisories, and RFC "Security
Considerations" sections, each row mapped to the `wired` code path it does
or does not apply to, one table row each. A row closes (`done`) only with
a verdict (`fixed` / `already-safe` / `n/a`) plus a real test function name,
or for `n/a` rows a one-line reason the class does not apply (no heap, no
hash table, no network client). `python3 scripts/vulnaudit/ledger_check.py
docs/security/vuln-ledger.md` machine-checks the row grammar and prints
per-section counts: QUIC transport 233, TLS 1.3 185, symmetric crypto 31,
signatures & key agreement 108, X.509/DER/PKI 131, HTTP/3+QPACK+Datagrams
68, WebTransport 21, MoQT 21, IP/UDP/AF_XDP 3, media (mp4frag) 25,
samples/dependencies 10 — all closed.

Many rows close `n/a` because the attacked mechanism does not exist here (no
heap allocator, so no UAF/double-free class; `conntable` is a fixed-size
linear scan, not a hash table, so no hash-DoS class). Three are explicit
**operator/deployment concerns**, not gaps this SDK can close in-process:

- **Revocation checking** (V-0324, RFC 8446 App. C.2, SHOULD) — this
  libc-free SDK ships no network client, so CRL fetch / OCSP stapling has
  nowhere to run.
- **Selfie / external-PSK reflection** (V-0300) — needs one endpoint sharing
  an external PSK across both client and server roles; this SDK has no
  external-PSK mechanism and the client role never accepts a ClientHello.
- **Self-marked ECN-CE suppression probe** (V-0223, RFC 9002 8.3, optional)
  — closes `already-safe` via the RFC 9000 13.4.2.1 count-floor check
  instead (`test_ecn_suppressed_counts_fail_validation`), since per-packet
  CE marking needs a per-send TOS `cmsg` the socket layer does not expose.

## Symmetric crypto & AEAD

- AEAD tag comparison is constant-time (XOR-OR accumulation, no early
  return) — `common/bytes/util/ct.h`, `gcm.c`, `chacha/aead.c` —
  `test_gcm_tamper_rejects`, `test_aead_tamper_rejects`.
- GCM and ChaCha20-Poly1305 round-trip against RFC/NIST vectors —
  `test_gcm_nist`, `test_chapoly_rfc`.
- Sender confidentiality limit triggers an automatic Key Update before nonce
  exhaustion (RFC 9001 6.6); a second update is refused before the peer
  acknowledges the first (6.2) — `test_srvloop_send_at_aead_limit_
  initiates_key_update`, `test_srvloop_no_second_update_before_peer_follows`.
- Integrity limit (decrypt-failure count) closes the connection with
  `AEAD_LIMIT_REACHED` (0x0f) — `test_srvrun_closes_with_aead_limit_
  reached_on_step`, `test_srvloop_recv_auth_failure_counts_toward_
  integrity_limit`.
- MACs go through HMAC (ipad/opad), closing length-extension — `test_hmac`
  suite. Poly1305 clamps `r` and derives its one-time key at counter 0 (RFC
  8439) — `test_poly1305` suite.
- `fuzz/fuzz_tlsmsg.c`, `fuzz/fuzz_frames.c` fuzz AEAD-adjacent framing and
  handshake-message parsing (`just fuzz-smoke` every push, `just fuzz-ci`
  nightly).

**Known limits:** the limit is enforced on the production send path
(`wired_srvloop_send_onertt`,
`test_srvloop_send_at_aead_limit_initiates_key_update`);
the older `connrunner_maybe_initiate_ku` helper is not used by the server
loop. An unacknowledged update stops sealing (RFC 9001 6.2 / 6.6) and the
idle timeout, not a dedicated close, ends the connection.

## Signatures & elliptic curves

- ECDSA rejects `r = 0`/`s = 0` and requires both scalars in `[1, n)`,
  closing the "Psychic Signature" class (CVE-2022-21449) — `test_ecdsa_
  verify` suite.
- ECDSA-Sig-Value DER decode rejects trailing bytes, extra elements,
  oversized/negative/empty integers, and non-minimal length/integer
  encoding (CVE-2018-1000180-class malleability) — `sig_value.c` —
  `test_sig_decode_rejects_trailing_data`, `test_sig_decode_rejects_
  oversized_integer`, `test_sig_decode_rejects_nonminimal_length`,
  `test_sig_decode_integer_padding`, `test_sig_decode_golden`.
- ECDSA signatures the SDK produces are low-S normalized (RFC 6979
  practice); verification still accepts standard high-S signatures.
- Ed25519 rejects non-canonical scalars and small-order/non-canonical `A`
  and `R` — `ed25519_field.c`, `ed25519_sign.c` — `test_ed25519_verify_
  rejects_small_order_key`, `test_ed25519_verify_rejects_small_order_r`,
  `test_ed25519_verify_rejects_noncanonical_key`, `test_ed25519_verify_
  rejects_noncanonical_r`.
- Public keys used in verification must lie on the curve and cannot be the
  point at infinity — `ecdsa_verify.c`, `p256_point.c`.
- A limb-boundary carry bug in the generic reduction (`fe_reduce_wide`/
  `fe6_reduce_wide` under-reducing at the `m<<256`/`m<<384` boundary) was
  found and fixed — `test_modexp_limb_boundary_square`, `test_p256_field_
  mul_all_ones_limbs`, `test_p384_field_mul_all_ones_limbs`.
- The fast P-256 verify path (fixed-base table + Montgomery reduction) is
  checked against a slow reference for differential correctness —
  `test_ecdsadiff_valid`, `test_ecdsadiff_tampered`, `test_ecdsadiff_edges`.
- ECDSA nonces are deterministic via HMAC-DRBG (RFC 6979) — `rfc6979.c`.
- `fuzz/fuzz_x509.c` fuzzes signature/DER decoding every push and nightly.

**Known limits:** the P-256/P-384 limb-boundary bug was a "contract bug" —
no current caller presented the wide input that triggers it, so it was not a
reachable verify bypass; fixed regardless. P-256 public-key loading does not
yet reject `x`/`y` `>= p` before the on-curve check; that check still
rejects such a point, so this is not a bypass.

## X25519 key agreement

- The shared secret is rejected when all-zero, which a low-order peer point
  produces (RFC 7748 6.1) — `x25519.c` — `test_x25519_low_order_rejected`.
- The rejection propagates through every ECDHE call site, aborting the
  handshake instead of deriving keys from a zero secret —
  `test_x25519_ecdhe`.
- The scalar is clamped per RFC 7748 — `test_x25519_clamp_rfc7748`,
  `test_x25519_clamp_does_not_mutate_input`.
- Field elements reduce fully mod `p = 2^255 - 19`, including the boundary
  where the value equals `p` (reduces to 0, not 19) — this is what lets a
  low-order point produce a true all-zero secret — `test_x25519_
  noncanonical_u_reduced`.
- Round-trips against RFC 7748 vectors (1 and 1000 iterations, Alice/Bob DH)
  — `test_x25519_rfc_v1`, `test_x25519_rfc_iterate_1000`, `test_x25519_
  rfc_dh_alice_bob`.

## Certificate chain & X.509

- Each link is verified: child issuer equals parent subject, parent key
  signs the child, tail anchored to a trust root — `pathvalidate.c`,
  `chainverify.c`.
- Every issuer must assert `basicConstraints cA = TRUE` (RFC 5280 6.1.4) via
  `x509_is_ca`; the leaf is not required to be a CA.
- The inner `tbsCertificate.signatureAlgorithm` must equal the outer OID
  (RFC 5280 4.1.1.2); mismatch rejected — `chainverify.c`.
- Name constraints (RFC 5280 4.2.1.10) accumulate across the whole chain:
  dNSName, iPAddress (address/mask, family mismatch, malformed-length
  subtree fail-closed), and DirectoryName (case-insensitive prefix) — 
  `nameconstraints.c`, `dirstring.c` — `test_ncsan_excluded_dns_wildcard_
  rejects`, `test_ncsan_permitted_ip4_outside_rejects`, `test_nc_excluded_
  dn_case_mismatch_rejects`, `test_ncx_excluded_in_a_survives_permitted_
  in_b`, `test_ncx_permitted_in_b_after_excluded_only_a_rejects`.
- CN-ID is only a fallback when no dNSName SAN exists — `san.c` —
  `test_ncsan_cn_fallback_outside_rejects`, `test_ncsan_san_present_
  cn_ignored`.
- Chain length and name-constraint subtree count are capped
  (CVE-2018-16875/CVE-2024-34702-class exhaustion) — `test_chain_over_
  cap_rejects`, `test_ncsan_subtree_count_over_cap_rejects`.
- Duplicate X.509 extensions are rejected (RFC 5280 4.2) —
  `test_x509_duplicate_extension_rejected`.
- PEM base64 decoding uses a branch-free byte classifier, not a
  secret-indexed table — `test_pem_every_byte_classified`.
- DER bounds every length (only `0x81`/`0x82` long forms, non-minimal
  long-form lengths rejected per X.690 10.1) — `der.c`, `derseq.c` —
  `test_sig_decode_rejects_nonminimal_length`.
- `fuzz/fuzz_x509.c` fuzzes certificate/DER decoding every push and nightly.
- **Caller responsibility, by role:** validity-time (`x509_validity_ok`) and
  hostname/SAN matching (`x509_san_matches`) need the application's clock
  and hostname. The **client role enforces this by default**:
  `client.c`'s `feed_initial()` always calls `fullhs_set_policy()` before
  authenticating the peer — no opt-out. The `fullhs` core and server role
  used standalone skip both checks.

**Known limits:** revocation checking is not implemented (see Audit ledger);
the RFC 5280 6.1.3(b) self-issued exemption is not implemented (over-rejects,
never bypasses); URI SAN name constraints fall back to fail-closed rather
than pattern-matching the URI — `test_ncsan_uri_excluded_with_uri_san_rejects`.

## QUIC

- Anti-amplification bounds server bytes sent before address validation
  (RFC 9000 8.1) — `antiamp.c`, `evloop.c`; 0-RTT acceptance and boot-time
  response volume are both gated on the same check — `test_srvrun_default_
  config_gates_response_volume_pre_validation`, `test_srvrun_0rtt_accept_
  requires_or_limits_unvalidated_address`. Initial packets pad to 1200
  bytes (RFC 9001 9.3) — `test_initpad`, `test_client_initial_padded`.
- Retry/stateless-reset tokens are HMAC-derived, constant-time compared, and
  length-checked against malformed input — `test_retrytoken_wire_verify_
  rejects_short_token`, `test_newtoken_wire_verify_rejects_long_token`,
  `test_retry_second_discarded`.
- ECN counts follow RFC 9000 13.4.2.1: a report whose ECT(0)+CE increase is
  smaller than newly-acked packets is rejected as suppressed, counts must be
  non-decreasing, and a reordered ACK that doesn't advance the largest-acked
  is never used for ECN validation — `ecn.c`, `srvloop.c` —
  `test_ecn_suppressed_counts_fail_validation`, `test_ecn_counts_valid_
  rejects_decrease_wired`, `test_srvloop_note_ecn_keeps_largest_ack`.
  Validated CE increases feed the congestion controller, floored at the
  minimum window — `test_ecn_inflated_ce_floors_at_min_window`,
  `test_srvrun_feed_acks_ecn_ce_shrinks_cwnd`.
- Flow control rejects data past MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS —
  `flow.c`, `stream_flow.c`, `streams.c`.
- STREAM final-size overflow and wrong-direction STREAM/STOP_SENDING are
  rejected (RFC 9000 19.5/19.8/4.5) — `test_frame_stream_final_size_
  overflow_rejected`, `test_dispatch_stop_sending_receive_only_rejected`.
- Path migration requires a fresh PATH_CHALLENGE on the new path (RFC 9000
  8.2.1/9.3) — `test_migrate_new_path_requires_fresh_validation`.
- A RESET_STREAM/STOP_SENDING flood (Rapid Reset, CVE-2023-44487) is
  rate-limited per connection in a 1s window, closing with
  `H3_EXCESSIVE_LOAD` (0x0107) past threshold; a server-wide cap separately
  bounds concurrent Extended CONNECT/WebTransport sessions — `srvloop.c`,
  `srvrun.c` — `test_srvrun_reset_flood_over_threshold_closes_
  excessive_load`, `test_srvrun_connect_concurrency_limit_enforced`.
- Version downgrade is detected and connection IDs come from the RNG —
  `version/downgrade.c`, `cidgen.c`.
- Server startup enforces a boot deadline against slow pre-authentication
  trickle connections; a reused connection slot's prior buffer is fully
  cleared — `test_srvrun_slow_trickle_preauth_evicted`, `test_srvrun_
  slot_reuse_clears_prior_connection_buffer`.
- `fuzz/fuzz_header.c`, `fuzz_onertt.c`, `fuzz_tlsmsg.c`, `fuzz_frames.c`
  fuzz varint/frame/0-RTT/handshake-message decoding, one iteration per
  push (`just fuzz-smoke`) and a bounded wall-clock budget nightly
  (`just fuzz-ci`).
- **Caller responsibility:** request-rate limiting beyond the built-in
  reset-flood counter, and Retry-token TTL.

## HTTP3 / QPACK

- QPACK decoding rejects output overflow and guards Huffman/integer
  decoding against overrun — `huffman.c`, `integer.c` — `test_huffman_
  overflow`. The dynamic table is bounded — `test_qpack_dyntable_bounded_
  by_max_entries`.
- Huffman decode cost is bounded by the fixed field-section cap and the
  table's own 30-bit maximum code length (RFC 9114 10.5.5 / QPACK §7,
  compression-cost DoS) — `test_qpack_huffman_decode_cost_bounded`.
- varint and frame parsers bound every read against the remaining buffer.
- A request body not streamed through an app's own
  `wired_srvrun_handler.on_body` is buffered up to one fixed window
  (`BODYWIN_CAP`, 2048 bytes); an overflow answers `413` (RFC 9110
  15.5.14), same as an app's `on_body` returning 0 to stop a body it
  decided is too large. An oversized leading HEADERS frame (the request's
  headers, not its body) answers `431` instead (RFC 6585 5) —
  `dispatch.c` — `test_srvrun_headers_over_req_buf_gets_431`, `test_
  srvrun_body_over_req_buf_gets_413`, `test_srvrun_full_window_body_
  gets_413`, `test_srvrun_full_window_headers_get_431`, `test_srvrun_
  on_body_reject_answers_413`, `test_srvrun_early_413_also_stops_sending`.
- `fuzz/fuzz_qpack.c` fuzzes QPACK decoding (`just fuzz-smoke` every push,
  `just fuzz-ci` nightly).

**Known limits:** `test_qpack_huffman_decode_cost_bounded` passes, but is
not mutation-killable through the `HUFF_MAXLEN` guard specifically — the
canonical Huffman table's longest code self-terminates before that guard is
reached, so the test proves the real claim (bounded decode time on
adversarial input) without exercising that guard as a failure lever
(V-0448). The Rapid Reset window override is only configurable via
`wired_srvrun_env`, not yet a public `wired_srvrun_opt` field.

## MOQT

- `src/app/moqt/` (`ctl`/`data`/`kvp`/`run`/`sess`/`vi`) implements MoQT
  (draft-ietf-moq-transport-19) over the WebTransport session and inherits
  its TLS 1.3 confidentiality/integrity and endpoint authentication — no
  separate MoQT-layer crypto exists.
- CONNECT-stream capsule decode/apply is wired so a pooled WebTransport
  session enforces flow control when sharing one QUIC connection
  (draft-ietf-webtrans-http3-15 5.1 MUST) — `wtcapsule.c`, `srvrun.c` —
  `test_srvrun_wt_session_sharing_enables_flow_control`, `test_srvrun_
  wt_rx_max_data_capsule_via_dispatch_unblocks_send`. Unknown capsules are
  skipped (RFC 9297 3.2), a malformed/truncated body closes the session
  (3.3), and a stale (lowering) flow-control value is ignored — `test_
  srvrun_wt_rx_unknown_capsule_via_dispatch_skipped`, `test_srvrun_wt_rx_
  truncated_capsule_via_dispatch_closes_session`, `test_srvrun_wt_ignores_
  stale_flow_control_capsules`.
- `WT_CLOSE_SESSION` ends the session; WebTransport session creation is
  rate-limited server-wide per window; usage counters (sessions/streams/
  datagrams) are exposed — `test_srvrun_wt_close_session_capsule_received`,
  `test_srvrun_wt_session_creation_rate_limited`, `test_srvrun_wt_usage_
  counters_exposed`.
- A present `Origin` header on an Extended CONNECT must be non-empty for the
  session to establish (draft-ietf-webtrans-http3-15 SS3.6); a malformed
  (empty) `Origin` is rejected with `403` — `wt_origin_ok` in `srvrun.c` —
  `test_srvrun_wt_connect_origin_ok_establishes`, `test_srvrun_wt_connect_
  origin_malformed_403`. An absent `Origin` is not itself a rejection reason
  (a non-browser client sends none).
- An application allowlist hooks in through `wired_srvrun_opt.wt_origin_check`
  (draft-ietf-webtrans-http3-15 SS3.1): after the empty-`Origin` rejection
  above (that `403` is sent before the callback runs), the callback sees the
  `Origin` value and `:authority` and returns 0 to answer `403` with no
  session; an absent `Origin` reaches it as an empty span. Unset, every
  well-formed `Origin` is accepted — `test_srvrun_wt_origin_check_allowed_
  establishes`, `test_srvrun_wt_origin_check_disallowed_403`, `test_srvrun_
  wt_origin_check_absent_empty_span`, `test_srvrun_wt_origin_check_unset_
  unchanged`.
- A peer's `WT_DRAIN_SESSION` reaches the app once per session through
  `wired_srvrun_opt.wt_on_session_draining` (draft-ietf-webtrans-http3-15
  4.7); one carrying a value is malformed (its Length is 0) and closes the
  session — `test_srvrun_wt_drain_rx_notifies_app`, `test_srvrun_wt_drain_
  rx_with_value_closes`.
- One-shot control frames (`WT_CLOSE_SESSION`, GOAWAY, an app-requested
  RESET_STREAM, the early-response STOP_SENDING) are kept until
  acknowledged and resent on loss, so a lossy peer cannot keep a session
  or request open by dropping them; a peer that never acknowledges within
  the resend budget gets its connection torn down —
  `test_srvrun_wt_close_capsule_retransmitted_after_loss`, `test_srvrun_
  control_packets_kept_until_acked`, `test_srvrun_rst_budget_exhausted_
  tears_down`.
- A varint length-overflow in object/property length parsing (`*at + len >
  buf.n` wrapping mod 2^64, an ~2^64-byte OOB decode span or infinite loop,
  found by `fuzz/fuzz_moqt.c`) was fixed by rewriting the check in
  non-overflowing subtraction form — `test_moqdata_obj_take_len_wrap`,
  `test_moqdata_obj_take_payload_len_boundary`, `test_moqvi_put_at_
  capacity_edge`.
- `AUTHORIZATION_TOKEN` (0x03) decodes on SUBSCRIBE/PUBLISH parameters
  (draft-19 10.2.2), and an authorization hook gates every SUBSCRIBE before
  routing (draft-19 13.3: "Relays will verify the token") — `moqctl.c`,
  `moqtrun.c` — `test_moqctl_params_auth_token_use_value_decode`, `test_
  moqctl_params_auth_token_scope_violation`, `test_moqtrun_subscribe_
  requires_authorization`, `test_moqtrun_subscribe_alias_token_rejected`.
- `fuzz/fuzz_capsule.c` fuzzes WebTransport capsules every push and nightly.
  `fuzz/fuzz_moqt.c` fuzzes MoQT decoding every push (`just fuzz-smoke`)
  and nightly (`just fuzz-ci`); its seed corpus carries the timeout input
  that found the length overflow above as a regression seed.
- **Caller responsibility:** what an `AUTHORIZATION_TOKEN` value actually
  authorizes, and rate-limiting subscription requests (draft-19 13.1,
  Subscription Amplification), are application-layer concerns; the SDK
  provides the wire format and the hook, not the policy.

**Known limits:** the authorization hook is opt-in — the sample hub ships
with `authorize_subscribe == 0`, fully open by default; PUBLISH is not
gated — SUBSCRIBE and TRACK_STATUS go through `authorize_subscribe`, and
PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE through the separate, also opt-in
`authorize_namespace`; a duplicate `AUTHORIZATION_TOKEN` in one message is
rejected as a generic duplicate-parameter VIOLATION rather than honoring the
spec's "MAY be repeated" allowance; `WT_DRAIN_SESSION` is advisory only —
the SDK notifies the app but does not close the session itself; `Origin`
verification accepts any well-formed, non-empty value unless the app
registers `wt_origin_check` — no allowlist ships by default.

## Freestanding attack surface

- `src/` links no libc: the freestanding `-ffreestanding -nostdlib` build
  (`just ninja`) is the proof. No `malloc`/`free` (fixed-size buffers), no
  `printf`/`scanf`, no `getenv`/`system`/`exec`, no `signal` handlers, no
  libc string functions — each verified absent from production sources.
  This is also why whole ledger classes (use-after-free, double-free,
  heap-allocator confusion, hash-table collision DoS) close `n/a`: the
  attacked mechanism does not exist here.
- Connection-state growth under a worst-case peer, and WebTransport stream
  churn, are bounded by fixed-capacity tables rather than an allocator —
  `test_srvrun_conn_state_growth_bounded_under_worst_case_peer`, `test_
  srvrun_wt_stream_churn_bounded_by_slot_table`.

---

**Next:** [Syscalls](syscalls.md) — every kernel call the SDK makes.
([all docs](README.md))
