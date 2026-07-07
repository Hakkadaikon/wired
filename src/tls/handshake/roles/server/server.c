#include "tls/handshake/roles/server/server.h"

#include "common/platform/keylog/keylog.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/srvfin/hsdone.h"
#include "tls/handshake/roles/srvfin/verify.h"
#include "transport/conn/loop/crecv/message.h"

/* RFC 9001 4 / 4.1.2, RFC 8446 4 / 4.4.4: server handshake orchestrator. */

static void srv_copy32(u8* dst, const u8* src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* Append msg into the raw transcript buffer (truncates silently at capacity;
 * the cap is sized for a full flight). Returns the new length. */
static usz srv_tr_add(wired_server* s, const u8* msg, usz len) {
  usz room = WIRED_SERVER_TRANSCRIPT_MAX - s->tr_len;
  usz n    = len < room ? len : room;
  for (usz i = 0; i < n; i++) s->tr[s->tr_len + i] = msg[i];
  s->tr_len += n;
  return s->tr_len;
}

void wired_server_init(wired_server* s, const wired_server_init_in* in) {
  quic_sdrv_init_in din = {
      in->server_priv_x25519, in->server_pub_x25519, in->cert_seed, in->chain,
      in->chain_count};
  srv_copy32(s->server_priv, in->server_priv_x25519);
  quic_sdrv_init(&s->sdrv, &din);
  quic_keysched_init(&s->sched);
  quic_keyset_init(&s->keys);
  quic_srvfin_state_init(&s->fin, &s->sched, &s->keys);
  quic_crecv_init(&s->crecv);
  s->fd                = -1;
  s->phase             = WIRED_SERVER_HS_INITIAL;
  s->hs_done_sent      = 0;
  s->tr_len            = 0;
  s->tr_through_sh     = 0;
  s->tr_through_flight = 0;
  s->keylog_path       = 0;
}

int wired_server_set_cids(wired_server* s, quic_span odcid, quic_span iscid) {
  return quic_sdrv_set_cids(&s->sdrv, odcid, iscid);
}

void wired_server_set_limits(
    wired_server* s,
    u64           max_data,
    u64           max_streams_bidi,
    u64           max_datagram_frame_size) {
  s->sdrv.limits.max_data                = max_data;
  s->sdrv.limits.max_streams_bidi        = max_streams_bidi;
  s->sdrv.limits.max_datagram_frame_size = max_datagram_frame_size;
}

void wired_server_set_keylog_path(wired_server* s, const char* path) {
  s->keylog_path = path;
}

/* RFC 8446 4.1.2: legacy_version(2) precedes ClientHello.random, both after
 * the 4-byte handshake header (QUIC_HS_HEADER) put_prefix wrote them at. */
#define SRV_CH_RANDOM_OFF (QUIC_HS_HEADER + 2)

/* Record ClientHello.random off ch_msg for later keylog lines; a no-op if
 * ch_msg is too short to carry it (already validated well-formed by
 * quic_sdrv_recv_client_hello, so this only guards the copy itself). */
static void srv_record_client_random(
    wired_server* s, const u8* ch_msg, usz ch_len) {
  if (ch_len < SRV_CH_RANDOM_OFF + 32u) return;
  srv_copy32(s->client_random, ch_msg + SRV_CH_RANDOM_OFF);
}

int wired_server_recv_initial(wired_server* s, const u8* ch_msg, usz ch_len) {
  if (s->phase != WIRED_SERVER_HS_INITIAL) return 0;
  if (!quic_sdrv_recv_client_hello(&s->sdrv, ch_msg, ch_len)) return 0;
  srv_record_client_random(s, ch_msg, ch_len);
  srv_tr_add(s, ch_msg, ch_len);
  s->phase = WIRED_SERVER_HS_CH_RECVD;
  return 1;
}

/* RFC 8446 7.1: derive the Handshake key set over the transcript through
 * ServerHello and install the Handshake-level keys. */
/* ECDHE shared secret then advance to the handshake secret. RFC 7748 6.1: a
 * low-order client key gives an all-zero secret; reject it. */
static int srv_derive_hs(wired_server* s, u8 ecdhe[QUIC_X25519_LEN]) {
  if (!quic_x25519(ecdhe, s->server_priv, s->sdrv.client_pub)) return 0;
  return quic_keysched_advance_handshake(
      &s->sched, quic_span_of(ecdhe, QUIC_X25519_LEN),
      quic_span_of(s->tr, s->tr_through_sh));
}

static int srv_install_hs_keys(wired_server* s) {
  u8                       ecdhe[QUIC_X25519_LEN];
  const quic_initial_keys* shs;
  if (!srv_derive_hs(s, ecdhe)) return 0;
  if (!quic_keysched_get(&s->sched, QUIC_KS_SERVER_HS, &shs)) return 0;
  return quic_keyset_install(&s->keys, QUIC_LEVEL_HANDSHAKE, shs);
}

/* Record the flight in the transcript and install the Handshake key. */
static int srv_after_flight(wired_server* s, const quic_sdrv_flight_out* out) {
  s->tr_through_sh     = srv_tr_add(s, out->sh->p, out->sh->len);
  s->tr_through_flight = srv_tr_add(s, out->hs->p, out->hs->len);
  return srv_install_hs_keys(s);
}

/* Build the flight via sdrv and finish the transcript/key bookkeeping. */
static int srv_emit_flight(
    wired_server* s, const u8* server_random, const quic_sdrv_flight_out* out) {
  if (!quic_sdrv_build_server_flight(&s->sdrv, server_random, out)) return 0;
  return srv_after_flight(s, out);
}

int wired_server_build_flight(
    wired_server* s, const u8* server_random, const quic_sdrv_flight_out* out) {
  if (s->phase != WIRED_SERVER_HS_CH_RECVD) return 0;
  if (!srv_emit_flight(s, server_random, out)) return 0;
  s->phase = WIRED_SERVER_HS_FLIGHT_SENT;
  return 1;
}

/* NSS Key Log Format (SSLKEYLOGFILE): a verified client Finished is the point
 * the client handshake traffic secret is known-good, the earliest safe moment
 * to log it (logging an unverified secret would leak a value never proven to
 * match the peer). No-op when no keylog path is set. */
static void srv_log_c_hs_traffic(const wired_server* s, const u8* c_traffic) {
  if (!s->keylog_path) return;
  wired_keylog_append(
      s->keylog_path, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", s->client_random,
      quic_span_of(c_traffic, QUIC_HKDF_PRK));
}

/* RFC 8446 4.4.4: verify the client Finished against the client handshake
 * traffic secret and the transcript hash through the server Finished. */
static int srv_verify_finished(wired_server* s, const u8* msg, usz len) {
  const u8*             hs;
  u8                    c_traffic[QUIC_HKDF_PRK], th[QUIC_SHA256_DIGEST];
  quic_derive_secret_in dsi;
  int                   ok;
  if (!quic_sdrv_handshake_secret(&s->sdrv, &hs)) return 0;
  dsi.secret   = hs;
  dsi.label    = quic_span_of((const u8*)"c hs traffic", 12);
  dsi.messages = quic_span_of(s->tr, s->tr_through_sh);
  quic_tls_derive_secret(&dsi, c_traffic);
  quic_sha256(s->tr, s->tr_through_flight, th);
  ok =
      quic_srvfin_verify_client_finished(quic_span_of(msg, len), c_traffic, th);
  if (ok) srv_log_c_hs_traffic(s, c_traffic);
  return ok;
}

/* RFC 8446 7.1: on a verified client Finished, complete the handshake. The
 * application_traffic_secret_0 is derived over the transcript through the
 * server Finished (tr_through_flight), NOT the client Finished, so both peers
 * reach the same 1-RTT keys. */
static int srv_complete(wired_server* s, const u8* msg, usz len) {
  (void)msg;
  (void)len;
  if (!quic_srvfin_complete(&s->fin, s->tr, s->tr_through_flight)) return 0;
  s->phase = WIRED_SERVER_HS_CONFIRMED;
  return 1;
}

/* Process the reassembled client Finished: verify, then complete only on a
 * match. The forged path returns 0 having promoted nothing. */
static int srv_on_finished(wired_server* s, const u8* msg, usz len) {
  if (s->phase != WIRED_SERVER_HS_FLIGHT_SENT) return 0;
  if (!srv_verify_finished(s, msg, len)) return 0;
  return srv_complete(s, msg, len);
}

int wired_server_feed(wired_server* s, const u8* crypto_payload, usz len) {
  const u8* msg;
  usz       mlen;
  if (!quic_crecv_collect(&s->crecv, crypto_payload, len)) return 0;
  if (!quic_crecv_complete_message(&s->crecv)) return 0;
  quic_crecv_message(&s->crecv, &msg, &mlen);
  return srv_on_finished(s, msg, mlen);
}

int wired_server_handshake_done(wired_server* s, quic_obuf* out) {
  if (!quic_srvfin_should_send_handshake_done(
          s->fin.confirmed, s->hs_done_sent))
    return 0;
  if (!quic_srvfin_handshake_done_frame(out->p, out->cap, &out->len)) return 0;
  s->hs_done_sent = 1;
  return 1;
}

int wired_server_is_confirmed(const wired_server* s) {
  return s->phase == WIRED_SERVER_HS_CONFIRMED;
}
