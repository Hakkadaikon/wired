#include "tls/handshake/roles/server/server_impl.h"

static void srv_keylog_line(
    const wired_server* s, const char* label, const u8* secret);
static usz  srv_ch_len(const wired_server* s);
static void srv_keylog_early(const wired_server* s);
static void srv_keylog_master(const wired_server* s);
static void srv_keylog(const wired_server* s, const u8* c_hs_traffic);
static int  srv_seed_kuswitch_recv(wired_server* s);
static int  srv_seed_kuswitch_send(wired_server* s);
static void srv_seed_kuswitch(wired_server* s);
static int  srv_complete(
    wired_server* s, const u8* msg, usz len, const u8* c_hs_traffic);
static int srv_on_finished(wired_server* s, const u8* msg, usz len);

/* NSS Key Log Format (SSLKEYLOGFILE, draft-ietf-tls-keylogfile 3/4): one
 * "<LABEL> <client_random> <secret>" line per secret. */
static void srv_keylog_line(
    const wired_server* s, const char* label, const u8* secret) {
  wired_keylog_append(
      s->keylog_path, label, s->client_random,
      wired_span_of(secret, server_srv_hash(s)->len));
}

/* RFC 8446 4.4.1: with 0-RTT accepted there was no HRR, so the transcript
 * opens with the ClientHello; its length is the 24-bit handshake header. */
static usz srv_ch_len(const wired_server* s) {
  return HS_HEADER + ((usz)s->tr[1] << 16 | (usz)s->tr[2] << 8 | s->tr[3]);
}

/* RFC 8446 7.1: client_early_traffic_secret, only when 0-RTT was accepted
 * (the PSK and ClientHello it is derived over are both retained). */
static void srv_keylog_early(const wired_server* s) {
  u8 secret[TLS_HASH_MAX];
  if (!s->sdrv.early_data_accepted) return;
  tls_early_traffic_secret_suite(
      s->sdrv.cipher_suite, s->sdrv.psk_secret,
      wired_span_of(s->tr, srv_ch_len(s)), secret);
  srv_keylog_line(s, "CLIENT_EARLY_TRAFFIC_SECRET", secret);
}

/* RFC 8446 7.1: secrets the confirmed key schedule retains, by label. */
static const struct {
  const char* label;
  int (*get)(const keysched*, const u8**);
} srv_keylog_sched[] = {
    {"CLIENT_TRAFFIC_SECRET_0", keysched_client_ap_secret},
    {"SERVER_TRAFFIC_SECRET_0", keysched_server_ap_secret},
    {"EXPORTER_SECRET", keysched_exporter_secret},
};

static void srv_keylog_master(const wired_server* s) {
  const u8* secret;
  for (usz i = 0; i < sizeof srv_keylog_sched / sizeof *srv_keylog_sched; i++)
    if (srv_keylog_sched[i].get(&s->sched, &secret))
      srv_keylog_line(s, srv_keylog_sched[i].label, secret);
}

/* A verified client Finished is the earliest point every secret is
 * known-good (logging an unverified one would leak a value never proven to
 * match the peer), so the whole log is written at confirmation. No-op when
 * no keylog path is set (opt-in). */
static void srv_keylog(const wired_server* s, const u8* c_hs_traffic) {
  if (!s->keylog_path) return;
  srv_keylog_early(s);
  srv_keylog_line(s, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", c_hs_traffic);
  srv_keylog_line(s, "SERVER_HANDSHAKE_TRAFFIC_SECRET", s->sdrv.s_hs_traffic);
  srv_keylog_master(s);
}

/* RFC 8446 7.1: on a verified client Finished, complete the handshake. The
 * application_traffic_secret_0 is derived over the transcript through the
 * server Finished (tr_through_flight), NOT the client Finished, so both peers
 * reach the same 1-RTT keys. */
/* RFC 9001 6: seed generation 0 of the peer-driven (recv) key schedule from
 * the just-confirmed client_ap keys/secret, so a later Key Update can
 * derive generation 1 (kuswitch/derive.h needs the secret, not just
 * key/iv/hp). */
static int srv_seed_kuswitch_recv(wired_server* s) {
  const initial_keys* client_ap;
  const u8*           secret;
  if (!keysched_get(&s->sched, KS_CLIENT_AP, &client_ap)) return 0;
  if (!keysched_client_ap_secret(&s->sched, &secret)) return 0;
  kuswitch_init(&s->ku, client_ap);
  bytes_memcpy(s->ku_secret, secret, server_srv_hash(s)->len);
  return 1;
}

/* RFC 9001 6.2: seed generation 0 of the send-side key schedule the same
 * way, in lockstep with the recv side, so this endpoint's own send keys can
 * be advanced once a peer update is confirmed. */
static int srv_seed_kuswitch_send(wired_server* s) {
  const initial_keys* server_ap;
  const u8*           secret;
  if (!keysched_get(&s->sched, KS_SERVER_AP, &server_ap)) return 0;
  if (!keysched_server_ap_secret(&s->sched, &secret)) return 0;
  kuswitch_init(&s->ku_send, server_ap);
  bytes_memcpy(s->ku_send_secret, secret, server_srv_hash(s)->len);
  return 1;
}

static void srv_seed_kuswitch(wired_server* s) {
  int recv_ok  = srv_seed_kuswitch_recv(s);
  int send_ok  = srv_seed_kuswitch_send(s);
  s->ku_seeded = recv_ok && send_ok;
}

static int srv_complete(
    wired_server* s, const u8* msg, usz len, const u8* c_hs_traffic) {
  if (!srvfin_complete(&s->fin, s->tr, s->tr_through_flight)) return 0;
  srv_keylog(s, c_hs_traffic);
  /* RFC 8446 4.6.1/7.1: resumption_master_secret needs the transcript
   * through the verified client Finished, not just through the server's
   * own Finished -- fold it in now that it has actually verified. */
  s->tr_through_client_fin = server_srv_tr_add(s, msg, len);
  srv_seed_kuswitch(s);
  /* RFC 9001 4.9.3: 1-RTT keys are installed now; the 0-RTT keys are no
   * longer needed and must not outlive the switch. */
  sdrv_discard_early_keys(&s->sdrv);
  s->phase = WIRED_SERVER_HS_CONFIRMED;
  return 1;
}

/* Process the reassembled client Finished: verify, then complete only on a
 * match. The forged path returns 0 having promoted nothing. */
static int srv_on_finished(wired_server* s, const u8* msg, usz len) {
  u8 c_traffic[TLS_HASH_MAX];
  if (s->phase != WIRED_SERVER_HS_FLIGHT_SENT) return 0;
  if (!server_srv_verify_finished(s, msg, len, c_traffic)) return 0;
  /* RFC 8446 7.1: fold exactly the verified Finished, whose body the
   * verify above pinned to Hash.length bytes -- the reassembled prefix
   * may run past it (bytes another packet smeared into the stream), and
   * folding the excess mints a resumption_master_secret no client can
   * match: every ticket from such a connection then fails its binder. */
  return srv_complete(s, msg, HS_HEADER + server_srv_hash(s)->len, c_traffic);
}

int wired_server_feed(wired_server* s, const u8* crypto_payload, usz len) {
  const u8* msg;
  usz       mlen;
  if (!crecv_collect(&s->crecv, crypto_payload, len)) return 0;
  if (!crecv_complete_message(&s->crecv)) return 0;
  crecv_message(&s->crecv, &msg, &mlen);
  return srv_on_finished(s, msg, mlen);
}

int wired_server_handshake_done(wired_server* s, wired_obuf* out) {
  if (!srvfin_should_send_handshake_done(s->fin.confirmed, s->hs_done_sent))
    return 0;
  if (!srvfin_handshake_done_frame(out->p, out->cap, &out->len)) return 0;
  s->hs_done_sent = 1;
  return 1;
}

int wired_server_early_data_used(const wired_server* s) {
  return s->sdrv.early_data_accepted;
}

int wired_server_is_confirmed(const wired_server* s) {
  return s->phase == WIRED_SERVER_HS_CONFIRMED;
}
