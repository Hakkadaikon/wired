#include "tls/keys/schedule_drive/keyschedule.h"

#include "tls/handshake/core/tls/appkeys.h"
#include "tls/handshake/core/tls/master.h"
#include "tls/handshake/core/tls/schedule.h"

void quic_keysched_init(quic_keysched* st) { st->stage = 0; }

/* RFC 8446 7.1: ECDHE shared secret is exactly 32 bytes (X25519 / P-256). */
static int ecdhe_ok(int stage, usz ecdhe_len) {
  return stage == 0 && ecdhe_len == 32;
}

int quic_keysched_advance_handshake(
    quic_keysched* st, quic_span ecdhe, quic_span transcript) {
  u8                     hs[QUIC_HKDF_PRK];
  quic_handshake_keys_in in;
  if (!ecdhe_ok(st->stage, ecdhe.n)) return 0;
  quic_tls_handshake_secret(ecdhe.p, hs);
  in.hs_secret  = hs;
  in.transcript = transcript;
  in.is_server  = 0;
  quic_tls_handshake_keys(&in, &st->keys[QUIC_KS_CLIENT_HS]);
  in.is_server = 1;
  quic_tls_handshake_keys(&in, &st->keys[QUIC_KS_SERVER_HS]);
  quic_tls_master_secret(hs, st->master);
  st->stage = 1;
  return 1;
}

int quic_keysched_advance_master(
    quic_keysched* st, const u8* transcript, usz transcript_len) {
  quic_app_keys_in in;
  if (st->stage != 1) return 0;
  in.master     = st->master;
  in.transcript = quic_span_of(transcript, transcript_len);
  in.is_server  = 0;
  quic_tls_app_keys(&in, &st->keys[QUIC_KS_CLIENT_AP]);
  in.is_server = 1;
  quic_tls_app_keys(&in, &st->keys[QUIC_KS_SERVER_AP]);
  st->stage = 2;
  return 1;
}

/* A which-index is available once its stage has been reached. */
static int have(int stage, int which) {
  return which <= QUIC_KS_SERVER_HS ? stage >= 1 : stage >= 2;
}

int quic_keysched_get(
    const quic_keysched* st, int which, const quic_initial_keys** out) {
  if (!have(st->stage, which)) return 0;
  *out = &st->keys[which];
  return 1;
}
