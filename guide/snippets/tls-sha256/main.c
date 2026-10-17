#define WIRED_MAIN
#include "wired.h"

int wired_main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  u8 digest[SHA256_DIGEST];
  wired_sha256((const u8*)"abc", 3, digest);
  wired_dprintf(2, "sha256(\"abc\") = %.*H\n", (int)sizeof digest, digest);
  return 0;
}
