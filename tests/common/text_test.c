#include "common/bytes/text/text.h"

#include <string.h>
#include <unistd.h>

#include "common/fmt/fmt.h"
#include "test.h"

/* Equivalence classes: equal, prefix either way, empty, differing byte. */
static void test_text_span_eq_cstr(void) {
  CHECK(wired_span_eq_cstr(wired_span_of((const u8*)"/stats", 6), "/stats"));
  CHECK(wired_span_eq_cstr(wired_span_of((const u8*)"", 0), ""));
  CHECK(!wired_span_eq_cstr(wired_span_of((const u8*)"/stat", 5), "/stats"));
  CHECK(!wired_span_eq_cstr(wired_span_of((const u8*)"/statsx", 7), "/stats"));
  CHECK(!wired_span_eq_cstr(wired_span_of((const u8*)"/stbts", 6), "/stats"));
  CHECK(!wired_span_eq_cstr(wired_span_of((const u8*)"", 0), "a"));
}

static void test_text_span_eq(void) {
  static const u8 a[] = {1, 2, 3}, b[] = {1, 2, 3}, c[] = {1, 2, 4};
  CHECK(wired_span_eq(wired_span_of(a, 3), wired_span_of(b, 3)));
  CHECK(wired_span_eq(wired_span_of(a, 0), wired_span_of(c, 0)));
  CHECK(!wired_span_eq(wired_span_of(a, 3), wired_span_of(c, 3)));
  CHECK(!wired_span_eq(wired_span_of(a, 2), wired_span_of(b, 3)));
}

/* Boundary: fits, exactly cap-1, truncated, cap 1, cap 0 writes nothing. */
static void test_text_span_to_cstr(void) {
  char       out[8];
  wired_span s = wired_span_of((const u8*)"/index.html", 11);
  CHECK(wired_span_to_cstr(out, sizeof out, wired_span_of(s.p, 6)) == 6);
  CHECK(memcmp(out, "/index", 7) == 0);
  CHECK(wired_span_to_cstr(out, sizeof out, wired_span_of(s.p, 7)) == 7);
  CHECK(memcmp(out, "/index.", 8) == 0);
  CHECK(wired_span_to_cstr(out, sizeof out, s) == 7);
  CHECK(memcmp(out, "/index.", 8) == 0);
  CHECK(wired_span_to_cstr(out, 1, s) == 0 && out[0] == 0);
  out[0] = 'x';
  CHECK(wired_span_to_cstr(out, 0, s) == 0 && out[0] == 'x');
}

/* Hex encoding: lowercase, two digits per byte, truncation at whole bytes. */
static void test_text_hex_encode(void) {
  static const u8 v[] = {0x00, 0x0f, 0xa5, 0xff};
  char            out[16];
  CHECK(wired_hex_encode(out, sizeof out, wired_span_of(v, 4)) == 8);
  CHECK(memcmp(out, "000fa5ff", 9) == 0);
  CHECK(wired_hex_encode(out, 6, wired_span_of(v, 4)) == 4);
  CHECK(memcmp(out, "000f", 5) == 0);
  CHECK(wired_hex_encode(out, 1, wired_span_of(v, 4)) == 0 && out[0] == 0);
  CHECK(wired_hex_encode(out, sizeof out, wired_span_of(v, 0)) == 0);
}

static void text_t_read(int fd, char* got, usz cap) {
  ssz n              = read(fd, got, cap - 1);
  got[n < 0 ? 0 : n] = 0;
}

/* Dumps write exactly the encoded bytes, longer than one internal chunk. */
static void test_text_dump(void) {
  static u8   big[300];
  static char got[1024], want[1024];
  int         fds[2];
  for (usz i = 0; i < sizeof big; i++) big[i] = (u8)i;
  CHECK(pipe(fds) == 0);
  wired_dump_hex(fds[1], wired_span_of(big, sizeof big));
  text_t_read(fds[0], got, sizeof got);
  for (usz i = 0; i < sizeof big; i++) sprintf(want + 2 * i, "%02x", big[i]);
  CHECK(strcmp(got, want) == 0);
  wired_dump_text(fds[1], wired_span_of((const u8*)"hello wired", 5));
  text_t_read(fds[0], got, sizeof got);
  CHECK(strcmp(got, "hello") == 0);
  close(fds[0]);
  close(fds[1]);
}

/* WIRED_SPAN_ARG prints exactly the view's bytes, not up to a NUL. */
static void test_text_span_arg(void) {
  char       out[32];
  wired_span s = wired_span_of((const u8*)"/stats?x", 6);
  CHECK(wired_snprintf(out, sizeof out, "[%.*s]", WIRED_SPAN_ARG(s)) == 8);
  CHECK(strcmp(out, "[/stats]") == 0);
  CHECK(
      wired_snprintf(
          out, sizeof out, "[%.*s]", WIRED_SPAN_ARG(wired_span_of(s.p, 0))) ==
      2);
}

static void test_text_span_cstr(void) {
  static const char lit[] = "location";
  wired_span        s     = wired_span_cstr(lit);
  CHECK(s.p == (const u8*)lit && s.n == 8);
  CHECK(wired_span_cstr("").n == 0);
}

/* First match index; -1 when absent or empty. */
static void test_text_span_find(void) {
  wired_span s = wired_span_cstr("a/b/c");
  CHECK(wired_span_find(s, '/') == 1);
  CHECK(wired_span_find(s, 'a') == 0);
  CHECK(wired_span_find(s, 'c') == 4);
  CHECK(wired_span_find(s, 'x') == -1);
  CHECK(wired_span_find(wired_span_of(s.p, 0), 'a') == -1);
}

void test_text(void) {
  test_text_span_find();
  test_text_span_cstr();
  test_text_span_arg();
  test_text_span_eq_cstr();
  test_text_span_eq();
  test_text_span_to_cstr();
  test_text_hex_encode();
  test_text_dump();
}
