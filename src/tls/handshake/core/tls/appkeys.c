#include "tls/handshake/core/tls/appkeys.h"

#include "tls/handshake/core/tls/schedule.h"

void quic_tls_app_keys(const quic_app_keys_in* in, quic_initial_keys* out) {
  const char* label = in->is_server ? "s ap traffic" : "c ap traffic";
  u8          ts[QUIC_HKDF_PRK];
  /* RFC 8446 7.1: application_traffic_secret_0. */
  quic_derive_secret_in dsi = {
      in->master, quic_span_of((const u8*)label, 12), in->transcript};
  quic_tls_derive_secret(&dsi, ts);
  /* RFC 9001 5.1: expand the QUIC packet-protection triple. */
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_label li = {"quic iv", 7, {0, 0}};
  quic_hkdf_label lh = {"quic hp", 7, {0, 0}};
  quic_hkdf_expand_label(ts, &lk, quic_mspan_of(out->key, QUIC_INITIAL_KEY));
  quic_hkdf_expand_label(ts, &li, quic_mspan_of(out->iv, QUIC_INITIAL_IV));
  quic_hkdf_expand_label(ts, &lh, quic_mspan_of(out->hp, QUIC_INITIAL_HP));
}
