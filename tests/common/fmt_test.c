#include "common/fmt/fmt.h"

#include "test.h"

static int fmt_t_eq(const char* a, const char* b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return *a == *b;
}

/* Hand-written expectation. */
#define FT(expect, ...)                                      \
  do {                                                       \
    char b_[256];                                            \
    usz  n_ = wired_snprintf(b_, sizeof b_, __VA_ARGS__);    \
    CHECK(fmt_t_eq(b_, expect));                             \
    CHECK(n_ == (usz)snprintf(b_, sizeof b_, "%s", expect)); \
  } while (0)

/* Differential against the host snprintf. */
#define FD(...)                                           \
  do {                                                    \
    char b_[256], h_[256];                                \
    usz  n_ = wired_snprintf(b_, sizeof b_, __VA_ARGS__); \
    int  m_ = snprintf(h_, sizeof h_, __VA_ARGS__);       \
    CHECK(fmt_t_eq(b_, h_) && n_ == (usz)m_);             \
  } while (0)

static void test_fmt_int(void) {
  FT("0", "%d", 0);
  FT("-9223372036854775808", "%lld", (long long)(-9223372036854775807LL - 1));
  FT("9223372036854775807", "%lld", 9223372036854775807LL);
  FT("18446744073709551615", "%llu", 18446744073709551615ULL);
  FT("18446744073709551615", "%zu", (usz)-1);
  FT("-2147483648", "%d", -2147483647 - 1);
  FT("4294967295", "%u", 4294967295u);
  FT("-1", "%hhd", 255);
  FT("65535", "%hu", -1);
  FT("-32768", "%hd", 32768);
  FT("42", "%i", 42);
  FT("ff", "%x", 255);
  FT("FF", "%X", 255);
  FT("0xff", "%#x", 255);
  FT("0", "%#x", 0);
  FT("0XFF", "%#X", 255);
  FT("ffffffffffffffff", "%lx", (unsigned long)-1);
  FT("ffffffff", "%x", -1);
}

static void test_fmt_flags(void) {
  FT("   42", "%5d", 42);
  FT("42   |", "%-5d|", 42);
  FT("00042", "%05d", 42);
  FT("-0042", "%05d", -42);
  FT("+42", "%+d", 42);
  FT(" 42", "% d", 42);
  FT("00042", "%.5d", 42);
  FT("  00042", "%7.5d", 42);
  FT("   42", "%05.2d", 42);
  FT("", "%.0d", 0);
  FT("  ", "%2.0d", 0);
  FT("0x00ff", "%#06x", 255);
  FT("   42", "%*d", 5, 42);
  FT("42   |", "%*d|", -5, 42);
  FT("00042", "%.*d", 5, 42);
  FT("42  |", "%-04d|", 42);
  FD("%08.3d|%-8d|%+5d|% 05d", 7, 7, 7, 7);
  FD("%#10x|%-#10X|%#.5x", 3054, 3054, 3054);
}

static void test_fmt_str(void) {
  FT("abc", "%s", "abc");
  FT("(null)", "%s", (char*)0);
  FT("ab", "%.2s", "abc");
  FT("  abc", "%5s", "abc");
  FT("abc  |", "%-5s|", "abc");
  FT("  ab", "%*.*s", 4, 2, "abc");
  FT("x", "%c", 'x');
  FT("  x", "%3c", 'x');
  FT("100%", "100%%");
  FT("%q", "%q");
  FT("0x1f", "%p", (void*)0x1f);
  FT("0x0", "%p", (void*)0);
  FT("0xdeadbeef", "%p", (void*)0xdeadbeefUL);
  FT("abc", "abc");
}

static void test_fmt_float(void) {
  FT("0.000000", "%f", 0.0);
  FT("-0.000000", "%f", -0.0);
  FT("1.500000", "%f", 1.5);
  FT("-1.500000", "%f", -1.5);
  FT("3.14", "%.2f", 3.14159);
  FT("3", "%.0f", 3.4);
  FT("4", "%.0f", 3.5);
  FT("2", "%.0f", 2.5);
  FT("0.12", "%.2f", 0.125);
  FT("0.38", "%.2f", 0.375);
  FT("1.0", "%.1f", 0.99);
  FT("10", "%.0f", 9.5);
  FT("100.00", "%.2f", 99.999);
  FT("3.", "%#.0f", 3.0);
  FT("+1.0", "%+.1f", 1.0);
  FT("  1.50", "%6.2f", 1.5);
  FT("1.50  |", "%-6.2f|", 1.5);
  FT("001.50", "%06.2f", 1.5);
  FT("-01.50", "%06.2f", -1.5);
  FT("nan", "%f", __builtin_nan(""));
  FT("inf", "%f", __builtin_inf());
  FT("-inf", "%f", -__builtin_inf());
  FT("   inf", "%6f", __builtin_inf());
  FT("   inf", "%06f", __builtin_inf());
  FT("18446744073709551615.000000", "%f", 1e30);
  FD("%f|%f|%f", 0.1, 123456.789, 1e-7);
  FD("%.10f|%.15f", 0.1, 1.0 / 3.0);
  FD("%.3f|%.3f|%.3f", 2.0005, 1e15, 4294967296.5);
  FD("%f", 5e-324);
  FD("%.20f", 0.1);
}

static void test_fmt_trunc(void) {
  char b[8] = "XXXXXXX";
  CHECK(wired_snprintf(b, 0, "%d", 12345) == 5);
  CHECK(b[0] == 'X');
  CHECK(wired_snprintf(b, 1, "%d", 12345) == 5);
  CHECK(b[0] == 0);
  CHECK(wired_snprintf(b, 3, "%d", 12345) == 5);
  CHECK(fmt_t_eq(b, "12"));
  CHECK(wired_snprintf(b, 6, "%d", 12345) == 5);
  CHECK(fmt_t_eq(b, "12345"));
  CHECK(wired_snprintf(b, 5, "%d", 12345) == 5);
  CHECK(fmt_t_eq(b, "1234"));
  CHECK(wired_snprintf(0, 0, "%s", "abc") == 3);
}

static void test_fmt_dprintf(void) {
  CHECK(wired_dprintf(-1, "x") < 0);
  CHECK(wired_dprintf(1, "") == 0);
  CHECK(wired_dprintf(1, "fmt-test %d %s\n", 7, "ok") == 14);
}

void test_fmt(void) {
  test_fmt_int();
  test_fmt_flags();
  test_fmt_str();
  test_fmt_float();
  test_fmt_trunc();
  test_fmt_dprintf();
}
