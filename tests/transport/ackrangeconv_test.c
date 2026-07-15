#include "test.h"

/* RFC 9000 19.3: quic_ackgen_build_ranges's gap-encoded output (largest +
 * First ACK Range Length + (Gap, Range Length) pairs) converts to
 * quic_ack_frame's explicit [hi, lo] range array, the format quic_ack_encode
 * requires. */
void test_ackrangeconv(void) {
  /* single contiguous block 3..7: one explicit range {7, 3}. */
  {
    u64            raw[1] = {4}; /* first range length: 5 pns -> len 4 */
    quic_ack_frame f      = {0};
    CHECK(quic_ackrangeconv_to_frame(7, raw, 1, &f) == 1);
    CHECK(f.n_ranges == 1);
    CHECK(f.ranges[0].hi == 7 && f.ranges[0].lo == 3);
  }

  /* two blocks 0..1 and 4..5 (gap=1 between them, RFC 19.3.1 example from
   * ackrange_test.c): explicit ranges {5,4} then {1,0}. */
  {
    u64            raw[3] = {1, 1, 1}; /* first_len, gap, second_len */
    quic_ack_frame f      = {0};
    CHECK(quic_ackrangeconv_to_frame(5, raw, 3, &f) == 1);
    CHECK(f.n_ranges == 2);
    CHECK(f.ranges[0].hi == 5 && f.ranges[0].lo == 4);
    CHECK(f.ranges[1].hi == 1 && f.ranges[1].lo == 0);
  }

  /* zero raw values (0 ranges written, e.g. quic_ackgen_build_ranges never
   * emits this but the converter must not crash / must reject) is invalid
   * input -- n must be odd count >=1 (1, 3, 5, ...). Even count is malformed.
   */
  {
    u64            raw[2] = {1, 1};
    quic_ack_frame f      = {0};
    CHECK(quic_ackrangeconv_to_frame(5, raw, 2, &f) == 0);
  }

  /* too many ranges for quic_ack_frame's fixed array (QUIC_ACK_MAX_RANGES)
   * fails cleanly instead of overflowing. */
  {
    u64            raw[2 * QUIC_ACK_MAX_RANGES + 1];
    quic_ack_frame f = {0};
    usz            i;
    raw[0] = 0;
    for (i = 1; i < sizeof(raw) / sizeof(raw[0]); i += 2) {
      raw[i]     = 0; /* gap */
      raw[i + 1] = 0; /* len */
    }
    CHECK(
        quic_ackrangeconv_to_frame(
            1000, raw, sizeof(raw) / sizeof(raw[0]), &f) == 0);
  }
}
