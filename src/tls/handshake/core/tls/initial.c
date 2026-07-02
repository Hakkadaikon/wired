#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.2 initial_salt. */
static const u8 INITIAL_SALT[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                    0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                    0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

/* Expand-Label one field from the per-side secret into out[0..len). */
static void derive_field(
    const u8 *secret, const char *label, usz label_len, u8 *out, usz len) {
  quic_hkdf_label l = {label, label_len, {0, 0}};
  quic_hkdf_expand_label(secret, &l, quic_mspan_of(out, len));
}

/* From the per-side initial secret, fill key/iv/hp (RFC 9001 5.1 labels). */
static void derive_keys(
    const u8 secret[QUIC_HKDF_PRK], quic_initial_keys *out) {
  derive_field(secret, "quic key", 8, out->key, QUIC_INITIAL_KEY);
  derive_field(secret, "quic iv", 7, out->iv, QUIC_INITIAL_IV);
  derive_field(secret, "quic hp", 7, out->hp, QUIC_INITIAL_HP);
}

void quic_initial_derive(
    const u8 *dcid, usz dcid_len, int is_server, quic_initial_keys *out) {
  u8          initial_secret[QUIC_HKDF_PRK];
  u8          side_secret[QUIC_HKDF_PRK];
  const char *label = is_server ? "server in" : "client in";
  quic_hkdf_extract(
      quic_span_of(INITIAL_SALT, 20), quic_span_of(dcid, dcid_len),
      initial_secret);
  derive_field(initial_secret, label, 9, side_secret, QUIC_HKDF_PRK);
  derive_keys(side_secret, out);
}
