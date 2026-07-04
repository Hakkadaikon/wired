#include "test.h"

/* wired_fio_read reads a whole file via raw syscalls. Fixtures are created
 * in build/ (gitignored, writable) with openat(O_CREAT|O_WRONLY|O_TRUNC)
 * and removed with unlinkat afterwards. */

#define SYS_unlinkat 263        /* unlinkat(2) */
#define FIOT_AT_FDCWD (-100)    /* openat/unlinkat: resolve against cwd */
#define FIOT_O_CREATE_WR 0x241u /* O_WRONLY|O_CREAT|O_TRUNC */
#define FIOT_MODE 0600          /* rw for owner */

static const char fiot_path[] = "build/fio_test.tmp";

static void fiot_make(const u8 *data, usz n) {
  i64 fd = syscall6(
      SYS_openat, FIOT_AT_FDCWD, (i64)fiot_path, FIOT_O_CREATE_WR, FIOT_MODE, 0,
      0);
  CHECK(fd >= 0);
  if (n) CHECK(syscall3(SYS_write, fd, data, n) == (i64)n);
  syscall1(SYS_close, fd);
}

static void fiot_unlink(void) {
  syscall3(SYS_unlinkat, FIOT_AT_FDCWD, fiot_path, 0);
}

/* Full round-trip: every written byte comes back, count is exact. */
static void test_fio_roundtrip(void) {
  u8 data[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
  u8 out[16] = {0};
  fiot_make(data, 5);
  CHECK(wired_fio_read(fiot_path, quic_mspan_of(out, sizeof out)) == 5);
  for (usz i = 0; i < 5; i++) CHECK(out[i] == data[i]);
  fiot_unlink();
}

/* Nonexistent path: openat's -errno is passed through (negative). */
static void test_fio_missing(void) {
  u8 out[4];
  CHECK(
      wired_fio_read(
          "build/fio_test_missing.tmp", quic_mspan_of(out, sizeof out)) < 0);
}

/* File size == buf.n exactly: success, not overflow. */
static void test_fio_exact_fit(void) {
  u8 data[4] = {9, 8, 7, 6};
  u8 out[4]  = {0};
  fiot_make(data, 4);
  CHECK(wired_fio_read(fiot_path, quic_mspan_of(out, sizeof out)) == 4);
  CHECK(out[3] == 6);
  fiot_unlink();
}

/* File larger than buf: the leftover is reported as WIRED_FIO_ETOOBIG. */
static void test_fio_overflow(void) {
  u8 data[5] = {1, 2, 3, 4, 5};
  u8 out[4];
  fiot_make(data, 5);
  CHECK(
      wired_fio_read(fiot_path, quic_mspan_of(out, sizeof out)) ==
      WIRED_FIO_ETOOBIG);
  fiot_unlink();
}

/* Empty file: zero bytes read. */
static void test_fio_empty(void) {
  u8 out[4];
  fiot_make(0, 0);
  CHECK(wired_fio_read(fiot_path, quic_mspan_of(out, sizeof out)) == 0);
  fiot_unlink();
}

/* wired_fio_append creates a fresh file on the first call, and a second call
 * adds after the first rather than overwriting it. */
static void test_fio_append_appends(void) {
  const u8 first[]  = {'a', 'b'};
  const u8 second[] = {'c', 'd'};
  fiot_unlink();
  CHECK(wired_fio_append(fiot_path, quic_span_of(first, 2)) == 2);
  CHECK(wired_fio_append(fiot_path, quic_span_of(second, 2)) == 2);
  {
    u8 out[8] = {0};
    CHECK(wired_fio_read(fiot_path, quic_mspan_of(out, sizeof out)) == 4);
    CHECK(out[0] == 'a' && out[1] == 'b' && out[2] == 'c' && out[3] == 'd');
  }
  fiot_unlink();
}

/* Zero-length append: no-op, still succeeds. */
static void test_fio_append_empty(void) {
  fiot_unlink();
  CHECK(wired_fio_append(fiot_path, quic_span_of(0, 0)) == 0);
  fiot_unlink();
}

void test_fio(void) {
  test_fio_roundtrip();
  test_fio_missing();
  test_fio_exact_fit();
  test_fio_overflow();
  test_fio_empty();
  test_fio_append_appends();
  test_fio_append_empty();
}
