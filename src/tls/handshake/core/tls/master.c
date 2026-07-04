#include "tls/handshake/core/tls/master.h"

#include "tls/handshake/core/tls/schedule.h"

void quic_tls_master_secret(
    const u8 hs_secret[QUIC_HKDF_PRK], u8 out[QUIC_HKDF_PRK]) {
  u8 zero[QUIC_HKDF_PRK] = {0};
  u8 derived[QUIC_HKDF_PRK];
  /* RFC 8446 7.1: derived = Derive-Secret(Handshake, "derived", ""). */
  quic_derive_secret_in in = {
      hs_secret, quic_span_of((const u8*)"derived", 7), quic_span_of(zero, 0)};
  quic_tls_derive_secret(&in, derived);
  /* Master Secret = HKDF-Extract(derived, 0). */
  quic_hkdf_extract(
      quic_span_of(derived, QUIC_HKDF_PRK), quic_span_of(zero, QUIC_HKDF_PRK),
      out);
}
