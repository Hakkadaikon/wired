#include "test.h"

/* wired_keylog_append builds one NSS Key Log Format line (SSLKEYLOGFILE):
 * "<Label> <ClientRandom-hex> <Secret-hex>\n", appended via
 * wired_fio_append. Fixtures live in build/ (gitignored, writable) and are
 * removed with unlinkat afterwards. */

#define SYS_unlinkat 263        /* unlinkat(2) */
#define KEYLOGT_AT_FDCWD (-100) /* unlinkat: resolve against cwd */

static const char keylogt_path[] = "build/keylog_test.tmp";

static void keylogt_unlink(void) {
  syscall3(SYS_unlinkat, KEYLOGT_AT_FDCWD, keylogt_path, 0);
}

/* zero client_random hex-encodes to 64 '0' chars. */
static const char keylogt_zero_cr_hex[] =
    "0000000000000000000000000000000000000000000000000000000000000000";

static void keylogt_check_line(
    const char *label, const char *cr_hex, const char *secret_hex) {
  u8  out[256] = {0};
  ssz n        = wired_fio_read(keylogt_path, quic_mspan_of(out, sizeof out));
  usz label_n  = 0;
  usz i;
  while (label[label_n]) label_n++;
  CHECK(n > 0);
  for (i = 0; label[i]; i++) CHECK(out[i] == (u8)label[i]);
  CHECK(out[label_n] == ' ');
  for (i = 0; cr_hex[i]; i++) CHECK(out[label_n + 1 + i] == (u8)cr_hex[i]);
  {
    usz secret_off = label_n + 1 + 64 + 1;
    for (i = 0; secret_hex[i]; i++)
      CHECK(out[secret_off + i] == (u8)secret_hex[i]);
    CHECK(out[secret_off + i] == '\n');
    CHECK((usz)n == secret_off + i + 1);
  }
}

/* known client_random (all zero) + secret -> exact expected line, lowercase
 * hex, space-separated, newline-terminated. */
static void test_keylog_append_known_vector(void) {
  u8 cr[32]      = {0};
  u8 secret[4]   = {0xde, 0xad, 0xbe, 0xef};
  const char *label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";

  keylogt_unlink();
  CHECK(
      wired_keylog_append(keylogt_path, label, cr, quic_span_of(secret, 4)) >
      0);
  keylogt_check_line(label, keylogt_zero_cr_hex, "deadbeef");
  keylogt_unlink();
}

/* a nonzero byte proves nibble order/case: 0x1f -> "1f", not "F1"/"1F". */
static void test_keylog_append_nibble_order_and_case(void) {
  u8 cr[32]         = {0};
  u8 secret[1]      = {0x1f};
  const char *label = "L";

  cr[0] = 0xa0;
  cr[31] = 0x09;

  keylogt_unlink();
  CHECK(
      wired_keylog_append(keylogt_path, label, cr, quic_span_of(secret, 1)) >
      0);
  {
    u8  out[256] = {0};
    ssz n = wired_fio_read(keylogt_path, quic_mspan_of(out, sizeof out));
    CHECK(n > 0);
    CHECK(out[2] == 'a' && out[3] == '0');   /* label(1) + ' '(1) */
    CHECK(out[2 + 62] == '0' && out[2 + 63] == '9');
    CHECK(out[2 + 64] == ' ');
    CHECK(out[2 + 65] == '1' && out[2 + 66] == 'f');
    CHECK(out[2 + 67] == '\n');
  }
  keylogt_unlink();
}

/* empty secret: still one space before the newline, no secret hex bytes. */
static void test_keylog_append_empty_secret(void) {
  u8 cr[32]         = {0};
  const char *label = "L";

  keylogt_unlink();
  CHECK(
      wired_keylog_append(keylogt_path, label, cr, quic_span_of(0, 0)) > 0);
  keylogt_check_line(label, keylogt_zero_cr_hex, "");
  keylogt_unlink();
}

/* secret too large for the internal line buffer -> WIRED_FIO_ETOOBIG, and
 * nothing is written. */
static void test_keylog_append_secret_too_big(void) {
  static u8   secret[512] = {0};
  const char *label       = "L";
  u8          cr[32]      = {0};

  keylogt_unlink();
  CHECK(
      wired_keylog_append(
          keylogt_path, label, cr, quic_span_of(secret, sizeof secret)) ==
      WIRED_FIO_ETOOBIG);
  {
    u8  out[8] = {0};
    ssz n      = wired_fio_read(keylogt_path, quic_mspan_of(out, sizeof out));
    CHECK(n < 0); /* file was never created */
  }
}

void test_keylog(void) {
  test_keylog_append_known_vector();
  test_keylog_append_nibble_order_and_case();
  test_keylog_append_empty_secret();
  test_keylog_append_secret_too_big();
}
