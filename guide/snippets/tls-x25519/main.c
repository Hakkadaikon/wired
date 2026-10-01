#define WIRED_MAIN
#include "wired.h"

/* There is no printf: print bytes as lowercase hex by hand. */
static void log_hex(const char* label, const u8* p, usz n) {
  static const char digits[] = "0123456789abcdef";
  char              s[3]     = {0};
  wired_log_str(label);
  for (usz i = 0; i < n; i++) {
    s[0] = digits[p[i] >> 4];
    s[1] = digits[p[i] & 15];
    wired_log_str(s);
  }
  wired_log_str("\n");
}

/* The private keys from RFC 7748 6.1. */
static const u8 alice_priv[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
    0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
    0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
static const u8 bob_priv[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
    0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
    0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};

int wired_main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  u8 alice_pub[32], bob_pub[32], alice_shared[32], bob_shared[32];
  wired_x25519_base(alice_pub, alice_priv);
  wired_x25519_base(bob_pub, bob_priv);
  /* Each side combines its own private key with the other's public key.
   * A 0 return means a low-order peer key: reject the handshake. */
  if (!wired_x25519(alice_shared, alice_priv, bob_pub)) return 1;
  if (!wired_x25519(bob_shared, bob_priv, alice_pub)) return 1;
  log_hex("alice public: ", alice_pub, 32);
  log_hex("bob public:   ", bob_pub, 32);
  log_hex("shared:       ", alice_shared, 32);
  u8 diff = 0;
  for (usz i = 0; i < 32; i++) diff |= alice_shared[i] ^ bob_shared[i];
  wired_log_str(diff ? "shared equal: no\n" : "shared equal: yes\n");
  return 0;
}
