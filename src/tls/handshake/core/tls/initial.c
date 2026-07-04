#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.2 initial_salt. */
static const u8 INITIAL_SALT[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                    0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                    0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

/* Expand-Label one field from the per-side secret into out. */
static void derive_field(const u8* secret, quic_span label, quic_mspan out) {
  quic_hkdf_label l = {(const char*)label.p, label.n, {0, 0}};
  quic_hkdf_expand_label(secret, &l, out);
}

/* From the per-side initial secret, fill key/iv/hp (RFC 9001 5.1 labels). */
static void derive_keys(
    const u8 secret[QUIC_HKDF_PRK], quic_initial_keys* out) {
  derive_field(
      secret, quic_span_of((const u8*)"quic key", 8),
      quic_mspan_of(out->key, QUIC_INITIAL_KEY));
  derive_field(
      secret, quic_span_of((const u8*)"quic iv", 7),
      quic_mspan_of(out->iv, QUIC_INITIAL_IV));
  derive_field(
      secret, quic_span_of((const u8*)"quic hp", 7),
      quic_mspan_of(out->hp, QUIC_INITIAL_HP));
}

void quic_initial_derive(
    quic_span dcid, int is_server, quic_initial_keys* out) {
  u8          initial_secret[QUIC_HKDF_PRK];
  u8          side_secret[QUIC_HKDF_PRK];
  const char* label = is_server ? "server in" : "client in";
  quic_hkdf_extract(quic_span_of(INITIAL_SALT, 20), dcid, initial_secret);
  derive_field(
      initial_secret, quic_span_of((const u8*)label, 9),
      quic_mspan_of(side_secret, QUIC_HKDF_PRK));
  derive_keys(side_secret, out);
}
