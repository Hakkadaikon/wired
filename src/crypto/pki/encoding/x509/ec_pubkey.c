#include "crypto/pki/encoding/x509/ec_pubkey.h"

/* SEC1 2.3.3. The BIT STRING value is 0x00 (unused bits) then the 65-byte
 * uncompressed point 0x04 || X || Y. */
static int is_uncompressed(quic_span key) {
  if (key.n != 66) return 0;
  return key.p[0] == 0x00 && key.p[1] == 0x04;
}

static void copy32(u8 dst[32], const u8* src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

int quic_x509_ec_pubkey(quic_span spki_key, u8 x[32], u8 y[32]) {
  if (!is_uncompressed(spki_key)) return 0;
  copy32(x, spki_key.p + 2);
  copy32(y, spki_key.p + 34);
  return 1;
}

/* The 98-byte P-384 uncompressed form: 0x00 0x04 || X48 || Y48. */
static int is_uncompressed384(quic_span key) {
  if (key.n != 98) return 0;
  return key.p[0] == 0x00 && key.p[1] == 0x04;
}

static void copy48(u8 dst[48], const u8* src) {
  for (usz i = 0; i < 48; i++) dst[i] = src[i];
}

int quic_x509_ec_pubkey384(quic_span spki_key, u8 x[48], u8 y[48]) {
  if (!is_uncompressed384(spki_key)) return 0;
  copy48(x, spki_key.p + 2);
  copy48(y, spki_key.p + 50);
  return 1;
}
