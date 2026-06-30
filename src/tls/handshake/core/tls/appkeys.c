#include "tls/handshake/core/tls/appkeys.h"

#include "tls/handshake/core/tls/schedule.h"

void quic_tls_app_keys(
    const u8           master[QUIC_HKDF_PRK],
    const u8          *transcript,
    usz                tlen,
    int                is_server,
    quic_initial_keys *out) {
  const char *label = is_server ? "s ap traffic" : "c ap traffic";
  u8          ts[QUIC_HKDF_PRK];
  /* RFC 8446 7.1: application_traffic_secret_0. */
  quic_tls_derive_secret(master, label, 12, transcript, tlen, ts);
  /* RFC 9001 5.1: expand the QUIC packet-protection triple. */
  quic_hkdf_expand_label(ts, "quic key", 8, 0, 0, out->key, QUIC_INITIAL_KEY);
  quic_hkdf_expand_label(ts, "quic iv", 7, 0, 0, out->iv, QUIC_INITIAL_IV);
  quic_hkdf_expand_label(ts, "quic hp", 7, 0, 0, out->hp, QUIC_INITIAL_HP);
}
