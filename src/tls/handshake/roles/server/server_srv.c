#include "tls/handshake/roles/server/server_impl.h"

static int srv_advance_handshake(wired_server* s, u8 ecdhe[X25519_LEN]);
static int srv_derive_hs(wired_server* s, u8 ecdhe[X25519_LEN]);
static int srv_install_hs_keys(wired_server* s);
static int srv_after_flight(wired_server* s, const sdrv_flight_out* out);
static int srv_emit_flight(
    wired_server* s, const u8* server_random, const sdrv_flight_out* out);

/* RFC 8446 7.1: the same PSK-vs-plain Handshake Secret branch
 * sdrv_flight.c's sdrv_derive_handshake_secret already establishes for
 * sdrv's own flight -- here for the connection's real packet-protection key
 * schedule, over the identical ecdhe (sdrv's own stored shared secret) and
 * the identical transcript-through-ServerHello, so both Handshake Secret
 * computations agree byte-for-byte whenever a PSK was accepted. */
static int srv_advance_handshake(wired_server* s, u8 ecdhe[X25519_LEN]) {
  wired_span ecdhe_span = wired_span_of(ecdhe, X25519_LEN);
  wired_span tr_span    = wired_span_of(s->tr, s->tr_through_sh);
  if (s->sdrv.psk_accepted)
    return keysched_advance_handshake_psk(
        &s->sched, wired_span_of(s->sdrv.psk_secret, server_srv_hash(s)->len),
        ecdhe_span, tr_span);
  return keysched_advance_handshake(&s->sched, ecdhe_span, tr_span);
}

/* RFC 8446 7.1: derive the Handshake key set over the transcript through
 * ServerHello and install the Handshake-level keys, reusing the ECDHE shared
 * secret sdrv's flight derivation already computed over the identical
 * (server_priv, client_pub) pair -- recomputing the scalar multiply here
 * doubled the per-connection ECDHE cost. RFC 7748 6.1's all-zero (low-order
 * client key) rejection already ran there: hs_ready is only set after the
 * shared secret passed it. */
static int srv_derive_hs(wired_server* s, u8 ecdhe[X25519_LEN]) {
  if (!s->sdrv.hs_ready) return 0;
  for (usz i = 0; i < X25519_LEN; i++) ecdhe[i] = s->sdrv.ecdhe_secret[i];
  keysched_set_suite(&s->sched, s->sdrv.cipher_suite);
  /* RFC 9369 3.3.1: Handshake/1-RTT packet-protection labels follow the
   * connection's negotiated version ("quicv2 " prefix under v2). */
  keysched_set_version(&s->sched, sdrv_wire_version(&s->sdrv));
  return srv_advance_handshake(s, ecdhe);
}

static int srv_install_hs_keys(wired_server* s) {
  u8                  ecdhe[X25519_LEN];
  const initial_keys* shs;
  if (!srv_derive_hs(s, ecdhe)) return 0;
  if (!keysched_get(&s->sched, KS_SERVER_HS, &shs)) return 0;
  return keyset_install(&s->keys, LEVEL_HANDSHAKE, shs);
}

/* Record the flight in the transcript and install the Handshake key. */
static int srv_after_flight(wired_server* s, const sdrv_flight_out* out) {
  s->tr_through_sh     = server_srv_tr_add(s, out->sh->p, out->sh->len);
  s->tr_through_flight = server_srv_tr_add(s, out->hs->p, out->hs->len);
  return srv_install_hs_keys(s);
}

/* Build the flight via sdrv and finish the transcript/key bookkeeping. */
static int srv_emit_flight(
    wired_server* s, const u8* server_random, const sdrv_flight_out* out) {
  if (!sdrv_build_server_flight(&s->sdrv, server_random, out)) return 0;
  return srv_after_flight(s, out);
}

int wired_server_build_flight(
    wired_server* s, const u8* server_random, const sdrv_flight_out* out) {
  if (s->phase != WIRED_SERVER_HS_CH_RECVD) return 0;
  if (!srv_emit_flight(s, server_random, out)) return 0;
  s->phase = WIRED_SERVER_HS_FLIGHT_SENT;
  return 1;
}

/* RFC 8446 4.4.4: verify the client Finished against the client handshake
 * traffic secret (written to c_traffic for the key log) and the transcript
 * hash through the server Finished. */
int server_srv_verify_finished(
    wired_server* s, const u8* msg, usz len, u8* c_traffic) {
  const u8*        hs;
  u8               th[TLS_HASH_MAX];
  derive_secret_in dsi;
  if (!sdrv_handshake_secret(&s->sdrv, &hs)) return 0;
  dsi.secret   = hs;
  dsi.label    = wired_span_of((const u8*)"c hs traffic", 12);
  dsi.messages = wired_span_of(s->tr, s->tr_through_sh);
  dsi.suite    = s->sdrv.cipher_suite;
  tls_derive_secret(&dsi, c_traffic);
  server_srv_hash(s)->digest(s->tr, s->tr_through_flight, th);
  return srvfin_verify_client_finished_suite(
      s->sdrv.cipher_suite, wired_span_of(msg, len), c_traffic, th);
}
