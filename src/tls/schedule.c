#include "tls/schedule.h"

void quic_tls_derive_secret(const u8 secret[QUIC_HKDF_PRK],
                            const char *label, usz label_len,
                            const u8 *messages, usz messages_len,
                            u8 out[QUIC_HKDF_PRK])
{
    u8 thash[QUIC_SHA256_DIGEST];
    quic_sha256(messages, messages_len, thash);
    quic_hkdf_expand_label(secret, label, label_len, thash, sizeof(thash),
                           out, QUIC_HKDF_PRK);
}

void quic_tls_handshake_secret(const u8 ecdhe[32], u8 out[QUIC_HKDF_PRK])
{
    u8 zero[QUIC_HKDF_PRK] = {0};
    u8 early[QUIC_HKDF_PRK];
    u8 derived[QUIC_HKDF_PRK];
    /* Early Secret = HKDF-Extract(0, 0). */
    quic_hkdf_extract(zero, QUIC_HKDF_PRK, zero, QUIC_HKDF_PRK, early);
    /* derived = Derive-Secret(Early, "derived", "") -- empty transcript. */
    quic_tls_derive_secret(early, "derived", 7, zero, 0, derived);
    /* Handshake Secret = HKDF-Extract(derived, ECDHE). */
    quic_hkdf_extract(derived, QUIC_HKDF_PRK, ecdhe, 32, out);
}

/* Expand one packet-protection field (RFC 9001 5.1 labels) from a secret. */
static void hs_field(const u8 secret[QUIC_HKDF_PRK], const char *label,
                     usz label_len, u8 *out, usz len)
{
    quic_hkdf_expand_label(secret, label, label_len, 0, 0, out, len);
}

void quic_tls_handshake_keys(const u8 hs_secret[QUIC_HKDF_PRK],
                             const u8 *transcript, usz transcript_len,
                             int is_server, quic_initial_keys *out)
{
    const char *label = is_server ? "s hs traffic" : "c hs traffic";
    u8 ts[QUIC_HKDF_PRK];
    quic_tls_derive_secret(hs_secret, label, 12, transcript, transcript_len, ts);
    hs_field(ts, "quic key", 8, out->key, QUIC_INITIAL_KEY);
    hs_field(ts, "quic iv", 7, out->iv, QUIC_INITIAL_IV);
    hs_field(ts, "quic hp", 7, out->hp, QUIC_INITIAL_HP);
}
