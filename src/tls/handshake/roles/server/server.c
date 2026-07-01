#include "tls/handshake/roles/server/server.h"

#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/srvfin/hsdone.h"
#include "tls/handshake/roles/srvfin/verify.h"
#include "transport/conn/loop/crecv/message.h"

/* RFC 9001 4 / 4.1.2, RFC 8446 4 / 4.4.4: server handshake orchestrator. */

static void srv_copy32(u8 *dst, const u8 *src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* Append msg into the raw transcript buffer (truncates silently at capacity;
 * the cap is sized for a full flight). Returns the new length. */
static usz srv_tr_add(quic_server *s, const u8 *msg, usz len) {
  usz room = QUIC_SERVER_TRANSCRIPT_MAX - s->tr_len;
  usz n    = len < room ? len : room;
  for (usz i = 0; i < n; i++) s->tr[s->tr_len + i] = msg[i];
  s->tr_len += n;
  return s->tr_len;
}

void quic_server_init(
    quic_server *s,
    const u8     server_priv_x25519[32],
    const u8     server_pub_x25519[32],
    const u8     cert_seed[32],
    const u8    *cert_der,
    usz          cert_len) {
  srv_copy32(s->server_priv, server_priv_x25519);
  quic_sdrv_init(
      &s->sdrv, server_priv_x25519, server_pub_x25519, cert_seed, cert_der,
      cert_len);
  quic_keysched_init(&s->sched);
  quic_keyset_init(&s->keys);
  quic_srvfin_state_init(&s->fin, &s->sched, &s->keys);
  quic_crecv_init(&s->crecv);
  s->fd                = -1;
  s->phase             = QUIC_SERVER_HS_INITIAL;
  s->hs_done_sent      = 0;
  s->tr_len            = 0;
  s->tr_through_sh     = 0;
  s->tr_through_flight = 0;
}

int quic_server_set_cids(
    quic_server *s,
    const u8    *odcid,
    u8           odcid_len,
    const u8    *iscid,
    u8           iscid_len) {
  return quic_sdrv_set_cids(&s->sdrv, odcid, odcid_len, iscid, iscid_len);
}

int quic_server_recv_initial(quic_server *s, const u8 *ch_msg, usz ch_len) {
  if (s->phase != QUIC_SERVER_HS_INITIAL) return 0;
  if (!quic_sdrv_recv_client_hello(&s->sdrv, ch_msg, ch_len)) return 0;
  srv_tr_add(s, ch_msg, ch_len);
  s->phase = QUIC_SERVER_HS_CH_RECVD;
  return 1;
}

/* RFC 8446 7.1: derive the Handshake key set over the transcript through
 * ServerHello and install the Handshake-level keys. */
/* ECDHE shared secret then advance to the handshake secret. RFC 7748 6.1: a
 * low-order client key gives an all-zero secret; reject it. */
static int srv_derive_hs(quic_server *s, u8 ecdhe[QUIC_X25519_LEN]) {
  if (!quic_x25519(ecdhe, s->server_priv, s->sdrv.client_pub)) return 0;
  return quic_keysched_advance_handshake(
      &s->sched, ecdhe, QUIC_X25519_LEN, s->tr, s->tr_through_sh);
}

static int srv_install_hs_keys(quic_server *s) {
  u8                       ecdhe[QUIC_X25519_LEN];
  const quic_initial_keys *shs;
  if (!srv_derive_hs(s, ecdhe)) return 0;
  if (!quic_keysched_get(&s->sched, QUIC_KS_SERVER_HS, &shs)) return 0;
  return quic_keyset_install(&s->keys, QUIC_LEVEL_HANDSHAKE, shs);
}

/* Record the flight in the transcript and install the Handshake key. */
static int srv_after_flight(
    quic_server *s, const u8 *sh, usz shl, const u8 *fl, usz fll) {
  s->tr_through_sh     = srv_tr_add(s, sh, shl);
  s->tr_through_flight = srv_tr_add(s, fl, fll);
  return srv_install_hs_keys(s);
}

/* Build the flight via sdrv and finish the transcript/key bookkeeping. */
static int srv_emit_flight(
    quic_server *s,
    const u8    *server_random,
    u8          *sh_out,
    usz          sh_cap,
    usz         *sh_len,
    u8          *fl_out,
    usz          fl_cap,
    usz         *fl_len) {
  if (!quic_sdrv_build_server_flight(
          &s->sdrv, server_random, sh_out, sh_cap, sh_len, fl_out, fl_cap,
          fl_len))
    return 0;
  return srv_after_flight(s, sh_out, *sh_len, fl_out, *fl_len);
}

int quic_server_build_flight(
    quic_server *s,
    const u8    *server_random,
    u8          *sh_out,
    usz          sh_cap,
    usz         *sh_len,
    u8          *flight_out,
    usz          flight_cap,
    usz         *flight_len) {
  if (s->phase != QUIC_SERVER_HS_CH_RECVD) return 0;
  if (!srv_emit_flight(
          s, server_random, sh_out, sh_cap, sh_len, flight_out, flight_cap,
          flight_len))
    return 0;
  s->phase = QUIC_SERVER_HS_FLIGHT_SENT;
  return 1;
}

/* RFC 8446 4.4.4: verify the client Finished against the client handshake
 * traffic secret and the transcript hash through the server Finished. */
static int srv_verify_finished(quic_server *s, const u8 *msg, usz len) {
  const u8 *hs;
  u8        c_traffic[QUIC_HKDF_PRK], th[QUIC_SHA256_DIGEST];
  if (!quic_sdrv_handshake_secret(&s->sdrv, &hs)) return 0;
  quic_tls_derive_secret(
      hs, "c hs traffic", 12, s->tr, s->tr_through_sh, c_traffic);
  quic_sha256(s->tr, s->tr_through_flight, th);
  return quic_srvfin_verify_client_finished(msg, len, c_traffic, th);
}

/* RFC 8446 7.1: on a verified client Finished, complete the handshake. The
 * application_traffic_secret_0 is derived over the transcript through the
 * server Finished (tr_through_flight), NOT the client Finished, so both peers
 * reach the same 1-RTT keys. */
static int srv_complete(quic_server *s, const u8 *msg, usz len) {
  (void)msg;
  (void)len;
  if (!quic_srvfin_complete(&s->fin, s->tr, s->tr_through_flight)) return 0;
  s->phase = QUIC_SERVER_HS_CONFIRMED;
  return 1;
}

/* Process the reassembled client Finished: verify, then complete only on a
 * match. The forged path returns 0 having promoted nothing. */
static int srv_on_finished(quic_server *s, const u8 *msg, usz len) {
  if (s->phase != QUIC_SERVER_HS_FLIGHT_SENT) return 0;
  if (!srv_verify_finished(s, msg, len)) return 0;
  return srv_complete(s, msg, len);
}

int quic_server_feed(quic_server *s, const u8 *crypto_payload, usz len) {
  const u8 *msg;
  usz       mlen;
  if (!quic_crecv_collect(&s->crecv, crypto_payload, len)) return 0;
  if (!quic_crecv_complete_message(&s->crecv)) return 0;
  quic_crecv_message(&s->crecv, &msg, &mlen);
  return srv_on_finished(s, msg, mlen);
}

int quic_server_handshake_done(quic_server *s, u8 *out, usz cap, usz *out_len) {
  if (!quic_srvfin_should_send_handshake_done(
          s->fin.confirmed, s->hs_done_sent))
    return 0;
  if (!quic_srvfin_handshake_done_frame(out, cap, out_len)) return 0;
  s->hs_done_sent = 1;
  return 1;
}

int quic_server_is_confirmed(const quic_server *s) {
  return s->phase == QUIC_SERVER_HS_CONFIRMED;
}
