#include "test.h"

/* wired_qlog_append frames a record as JSON-SEQ (RFC 7464): RS (0x1E) +
 * record + LF, appended via wired_fio_append. Fixtures are created in
 * build/ (gitignored, writable) and removed with unlinkat afterwards. */

#define SYS_unlinkat 263      /* unlinkat(2) */
#define QLOGT_AT_FDCWD (-100) /* unlinkat: resolve against cwd */

static const char qlogt_path[] = "build/qlog_test.tmp";

static void qlogt_unlink(void) {
  syscall3(SYS_unlinkat, QLOGT_AT_FDCWD, qlogt_path, 0);
}

/* One record: framed as RS + text + LF, nothing more. */
static void test_qlog_append_frames_one_record(void) {
  const u8 rec[] = "{\"a\":1}";
  qlogt_unlink();
  CHECK(
      wired_qlog_append(qlogt_path, quic_span_of(rec, sizeof(rec) - 1)) ==
      (ssz)(sizeof(rec) - 1 + 2));
  {
    u8  out[32] = {0};
    ssz n       = wired_fio_read(qlogt_path, quic_mspan_of(out, sizeof out));
    CHECK(n == (ssz)(sizeof(rec) - 1 + 2));
    CHECK(out[0] == 0x1E);
    for (usz i = 0; i < sizeof(rec) - 1; i++) CHECK(out[1 + i] == (u8)rec[i]);
    CHECK(out[n - 1] == '\n');
  }
  qlogt_unlink();
}

/* A second append call adds another RS-framed record after the first, so a
 * reader can resynchronize on either RS boundary. */
static void test_qlog_append_multiple_records(void) {
  const u8 rec1[] = "{\"a\":1}";
  const u8 rec2[] = "{\"b\":2}";
  qlogt_unlink();
  CHECK(
      wired_qlog_append(qlogt_path, quic_span_of(rec1, sizeof(rec1) - 1)) > 0);
  CHECK(
      wired_qlog_append(qlogt_path, quic_span_of(rec2, sizeof(rec2) - 1)) > 0);
  {
    u8  out[64] = {0};
    ssz n       = wired_fio_read(qlogt_path, quic_mspan_of(out, sizeof out));
    ssz want    = (ssz)(2 * (sizeof(rec1) - 1 + 2));
    CHECK(n == want);
    /* second record's RS starts right after the first record's LF */
    usz second_rs = sizeof(rec1) - 1 + 2;
    CHECK(out[0] == 0x1E);
    CHECK(out[second_rs] == 0x1E);
  }
  qlogt_unlink();
}

/* Empty record: still framed (RS + LF only), not rejected. */
static void test_qlog_append_empty_record(void) {
  qlogt_unlink();
  CHECK(wired_qlog_append(qlogt_path, quic_span_of(0, 0)) == 2);
  {
    u8  out[4] = {0};
    ssz n      = wired_fio_read(qlogt_path, quic_mspan_of(out, sizeof out));
    CHECK(n == 2);
    CHECK(out[0] == 0x1E && out[1] == '\n');
  }
  qlogt_unlink();
}

void test_qlog(void) {
  test_qlog_append_frames_one_record();
  test_qlog_append_multiple_records();
  test_qlog_append_empty_record();
}
