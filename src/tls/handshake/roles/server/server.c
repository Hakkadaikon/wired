#include "tls/handshake/roles/server/server_impl.h"

static void srv_copy32(u8* dst, const u8* src);
static void srv_record_client_random(
    wired_server* s, const u8* ch_msg, usz ch_len);
static int srv_accept_client_hello(
    wired_server* s, const u8* ch_msg, usz ch_len);
static int srv_fold_ch(wired_server* s, const u8* ch_msg, usz ch_len);
static int srv_hrr_ready(const wired_server* s);

/* RFC 9001 4 / 4.1.2, RFC 8446 4 / 4.4.4: server handshake orchestrator. */

static void srv_copy32(u8* dst, const u8* src) {
  for (usz i = 0; i < 32; i++) {
    dst[i] = src[i];
  }
}

/* RFC 8446 B.4: the negotiated suite's hash (secrets are Hash.length). */
const tls_hash* server_srv_hash(const wired_server* s) {
  return tls_hash_of(s->sdrv.cipher_suite);
}

/* Append msg into the raw transcript buffer (truncates silently at capacity;
 * the cap is sized for a full flight). Returns the new length. */
usz server_srv_tr_add(wired_server* s, const u8* msg, usz len) {
  usz room = WIRED_SERVER_TRANSCRIPT_MAX - s->tr_len;
  usz n    = len < room ? len : room;
  for (usz i = 0; i < n; i++) {
    s->tr[s->tr_len + i] = msg[i];
  }
  s->tr_len += n;
  return s->tr_len;
}

void wired_server_init(wired_server* s, const wired_server_init_in* in) {
  sdrv_init_in din = {in->server_priv_x25519, in->server_pub_x25519,
                      in->cert_seed,          in->chain,
                      in->chain_count,        in->san_ipv4,
                      in->now_secs,           in->ticket_key};
  srv_copy32(s->server_priv, in->server_priv_x25519);
  sdrv_init(&s->sdrv, &din);
  keysched_init(&s->sched);
  keyset_init(&s->keys);
  srvfin_state_init(&s->fin, &s->sched, &s->keys);
  crecv_init(&s->crecv);
  s->fd                = -1;
  s->phase             = WIRED_SERVER_HS_INITIAL;
  s->hs_done_sent      = 0;
  s->tr_len            = 0;
  s->tr_through_sh     = 0;
  s->tr_through_flight = 0;
  s->keylog_path       = 0;
  s->ku_seeded         = 0;
  s->ku_send_count     = 0;
  s->ku_auth_fail      = 0;
}

int wired_server_set_cids(wired_server* s, wired_span odcid, wired_span iscid) {
  return sdrv_set_cids(&s->sdrv, odcid, iscid);
}

void wired_server_set_limits(
    wired_server* s,
    u64           max_data,
    u64           max_streams_bidi,
    u64           max_streams_uni,
    u64           max_datagram_frame_size) {
  s->sdrv.limits.max_data                = max_data;
  s->sdrv.limits.max_streams_bidi        = max_streams_bidi;
  s->sdrv.limits.max_streams_uni         = max_streams_uni;
  s->sdrv.limits.max_datagram_frame_size = max_datagram_frame_size;
}

void wired_server_set_reset_token(wired_server* s, const u8 token[16]) {
  for (usz i = 0; i < 16; i++) {
    s->sdrv.sreset_token[i] = token[i];
  }
  s->sdrv.sreset_token_set = 1;
}

void wired_server_set_keylog_path(wired_server* s, const char* path) {
  s->keylog_path = path;
}

/* Record ClientHello.random off ch_msg for later keylog lines; a no-op if
 * ch_msg is too short to carry it (already validated well-formed by
 * sdrv_recv_client_hello, so this only guards the copy itself). */
static void srv_record_client_random(
    wired_server* s, const u8* ch_msg, usz ch_len) {
  if (ch_len < SRV_CH_RANDOM_OFF + 32u) {
    return;
  }
  srv_copy32(s->client_random, ch_msg + SRV_CH_RANDOM_OFF);
}

/* Accept the ClientHello into sdrv and, RFC 6066 3, enforce unrecognized_name
 * on an SNI mismatch instead of sdrv's default silent-continue. Split out of
 * wired_server_recv_initial to keep its own CCN flat. */
static int srv_accept_client_hello(
    wired_server* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_recv_client_hello(&s->sdrv, ch_msg, ch_len)) {
    return 0;
  }
  return sdrv_enforce_sni(&s->sdrv);
}

/* Fold the accepted ClientHello into the raw transcript and advance the
 * phase -- skipped for an HRR-bound ClientHello1 (RFC 8446 4.4.1: it is
 * replaced by the message_hash synthetic message in wired_server_build_hrr,
 * and the phase stays HS_INITIAL so the retried ClientHello2 re-enters
 * wired_server_recv_initial). */
static int srv_fold_ch(wired_server* s, const u8* ch_msg, usz ch_len) {
  if (sdrv_hrr_pending(&s->sdrv)) {
    return 1;
  }
  server_srv_tr_add(s, ch_msg, ch_len);
  s->phase = WIRED_SERVER_HS_CH_RECVD;
  return 1;
}

int wired_server_recv_initial(wired_server* s, const u8* ch_msg, usz ch_len) {
  if (s->phase != WIRED_SERVER_HS_INITIAL) {
    return 0;
  }
  if (!srv_accept_client_hello(s, ch_msg, ch_len)) {
    return 0;
  }
  srv_record_client_random(s, ch_msg, ch_len);
  return srv_fold_ch(s, ch_msg, ch_len);
}

/* Phase and driver agree an HRR is what this connection owes next. */
static int srv_hrr_ready(const wired_server* s) {
  return s->phase == WIRED_SERVER_HS_INITIAL && sdrv_hrr_pending(&s->sdrv);
}

int wired_server_build_hrr(wired_server* s, wired_obuf* out) {
  u8  mh[4 + TLS_HASH_MAX];
  usz mh_len;
  if (!srv_hrr_ready(s)) {
    return 0;
  }
  if (!sdrv_build_hrr(&s->sdrv, out)) {
    return 0;
  }
  /* RFC 8446 4.4.1: the raw transcript restarts as
   * message_hash(Hash(ClientHello1)) || HRR, mirroring the hashed
   * transcript sdrv_build_hrr just reset -- ClientHello1 itself was never
   * folded in (srv_fold_ch skipped it). */
  mh_len = hrr_message_hash(
      s->sdrv.ch1_hash, server_srv_hash(s)->len, mh, sizeof mh);
  s->tr_len = 0;
  server_srv_tr_add(s, mh, mh_len);
  server_srv_tr_add(s, out->p, out->len);
  return 1;
}
