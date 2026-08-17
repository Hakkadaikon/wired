#include "tls/handshake/core/tls/master.h"

#include "tls/handshake/core/tls/schedule.h"

void tls_master_secret(const u8 hs_secret[HKDF_PRK], u8 out[HKDF_PRK]) {
  u8 zero[HKDF_PRK] = {0};
  u8 derived[HKDF_PRK];
  /* RFC 8446 7.1: derived = Derive-Secret(Handshake, "derived", ""). */
  derive_secret_in in = {
      hs_secret, wired_span_of((const u8*)"derived", 7),
      wired_span_of(zero, 0)};
  tls_derive_secret(&in, derived);
  /* Master Secret = HKDF-Extract(derived, 0). */
  hkdf_extract(
      wired_span_of(derived, HKDF_PRK), wired_span_of(zero, HKDF_PRK), out);
}
