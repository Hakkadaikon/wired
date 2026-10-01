#define WIRED_MAIN
#include "wired.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* There is no printf: print bytes as lowercase hex by hand. */
static void log_hex(const u8* p, usz n) {
  static const char digits[] = "0123456789abcdef";
  char              s[3]     = {0};
  for (usz i = 0; i < n; i++) {
    s[0] = digits[p[i] >> 4];
    s[1] = digits[p[i] & 15];
    wired_log_str(s);
  }
}

int wired_main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  u8 digest[SHA256_DIGEST];
  wired_sha256((const u8*)"abc", 3, digest);
  wired_log_str("sha256(\"abc\") = ");
  log_hex(digest, sizeof digest);
  wired_log_str("\n");
  return 0;
}
