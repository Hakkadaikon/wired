/* libFuzzer harness for the invariant packet-header parser (RFC 9000 17)
 * and the coalesced-datagram splitter (RFC 9000 12.2). Hosted build only —
 * mirrors tests/run.c's unity-include style, but this file itself may use
 * the standard library since it lives outside src/. */
#include <stddef.h>
#include <stdint.h>

#include "common/bytes/varint/varint.c"
#include "transport/packet/header/packet/header.c"
#include "transport/packet/header/packet/coalesce.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const u8 *buf = (const u8 *)data;
  usz       n   = (usz)size;

  if (n == 0) return 0;

  /* wired_header_parse: for a short header the caller must preset
   * dcid_len. Seed it from the first input byte so the fuzzer can reach
   * both the long- and short-header, both-fits and truncated paths. Zero
   * the rest so a build_long round-trip below never reads uninitialized
   * fields when parse only partially fills h (ASan alone can't catch that,
   * but there's no reason to leave it uninitialized either). */
  wired_header h = {0};
  h.dcid_len     = (u8)(buf[0] % (WIRED_MAX_CID_LEN + 1));
  wired_header_parse(buf, n, &h);

  /* wired_header_build_long round-trip on whatever wired_header_parse
   * produced (or partially produced) above, into a fixed local buffer. */
  u8 out[256];
  wired_header_build_long(out, sizeof(out), &h);

  /* quic_coalesce_next: walk every coalesced packet in the datagram. A
   * non-terminating loop here is itself a bug worth finding, so let
   * libFuzzer's -timeout catch it rather than papering over it with an
   * iteration cap. */
  quic_coalesce_iter it;
  quic_coalesce_begin(&it, buf, n);
  quic_coalesced pkt;
  while (quic_coalesce_next(&it, &pkt)) {}

  return 0;
}
