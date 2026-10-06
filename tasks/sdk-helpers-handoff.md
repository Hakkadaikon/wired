# SDK helper extraction — handoff (2026-10-05)

Goal (user): pull the boilerplate that is not the point of each sample
(string length, span compare, hex/struct dumps, ...) out of guide/snippets
and examples into the SDK, so samples keep only their main line.

## Done (this commit)

New SDK API (TDD; tests in tests/common/text_test.c, tests/common/fmt_test.c,
tests/app/srvboot_demo_test.c, tests/app/h3reqdrive_test.c; listed in
docs/api-stability.md):

| API | Replaced in samples |
|---|---|
| `wired_srvboot_demo` + `wired_srvboot_demo_keys` (srvboot/srvdemo.h) | the 15-line priv/seed/rnd/x25519/id block in 30 snippets; `server_identity` bodies in all 4 examples |
| `wired_srvboot_cert_sha256`, `wired_srvboot_log_fingerprint` | `log_cert_fingerprint` (wt-browser, moqt_chat) |
| `wired_span_eq_cstr`, `wired_span_eq`, `wired_span_cstr`, `wired_span_to_cstr`, `WIRED_SPAN_ARG` (common/bytes/text/text.h) | `len`, `span_is`, `is`, `path_is`, `field_is`, `track_name_is`, `fp_eq`, `reqpath_copy`, `log_span` (both forms), `mem_eq`/`span_eq_cstr`/`span_eq`/`str_eq`/`bytes_same` in examples |
| `wired_hex_encode`, `wired_dump_hex`, `wired_dump_text` | `log_hex` (quic-header, tls-x25519, ops-cert-reload) |
| `wired_obuf_printf` (common/fmt/fmt.h) | `put_str`/`put_u64` (h3-stats), memcpy+len body writes (h3-hello, h3-routing, h3-status-headers, h3-static-files, h3-post-body, ops-*) |
| `wired_h3req_path` (request_drive.h) | `wired_span_of(req->path, req->path_len)` |
| existing `wired_moqraw_io()` (was unused by snippets) | `with_signal`/`open_bidi`/`send_uni`/`open_uni_stream` + hand-built io tables in all 8 moqt-* snippets |

Verified: just test / test-fast, just ninja, lizard CCN<=3, fmt-check, docs,
object==source count, all 4 examples build, guide-verify 36/36 goldens
unchanged, guide pnpm test 91/91 (moqrawio.h added to snippet-lint allow
list). Not run: just fuzz-smoke (no existing signature changed), guide
pnpm build / test:dist.

Note: snippets/examples are outside fmt-check's scope; this commit ran the
pinned clang-format over the touched ones, so some diffs are line rewraps.

## Done (second round, 2026-10-06)

- `wired_fio_read_span` replaced `read_file` (tls-certificates).
- `wired_http_add_field` replaced `set_header` (h3-status-headers).
- `wired_http_reply_text` replaced `reply` (h3-routing, h3-status-headers)
  and `not_found` (h3-static-files).
- `wired_span_find` replaced `span_find` (examples/webtransport_interop).

## Left (not done, by priority) — items 1-3 and span_find above are done

1. `read_file` (tls-certificates): wired_fio_read -> span. Candidate:
   `wired_fio_read_span(path, buf, cap)` returning a `wired_span` (n=0 on
   error) in common/platform/fio.
2. `set_header` (h3-status-headers): candidate `wired_http_field_of(name,
   value)` from two C strings.
3. `reply` (h3-routing, h3-status-headers): status + text/plain + body is
   repeated; candidate `wired_http_reply_text(x, status, text)`.
4. examples/webtransport_interop: `cstr_len_opt`, `span_find`, `cat_str`,
   `cat_span`, `strip_slash`, `token_end` are generic text helpers that
   belong in text.h (`wired_span_find`, a cursor append); the rest
   (sessions, streams, downloads) is that example's own logic.
5. examples/moqt_chat `log_append_span`, word_list request parsing: same
   pattern, review after 4.
6. Snippet comments "A fixed demo identity: X25519 key share, ..." could be
   shortened now that wired_srvboot_demo documents it.

Kept on purpose (main line, not boilerplate): moqt-live `send_uni2` slot
ring, wt-session-lifecycle `find`, ops-cert-reload `report_cert`, every
authorize/on_* callback.
