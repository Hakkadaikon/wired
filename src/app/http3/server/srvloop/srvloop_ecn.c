#include "app/http3/server/srvloop/srvloop_impl.h"

static void srvloop_init_violation(wired_srvloop* l);
static void srvloop_init_ctrl(wired_srvloop* l);

/* Protocol violation latches and peer limits. */
static void srvloop_init_violation(wired_srvloop* l) {
  l->datagram_violation             = 0;
  l->priupdate_violation            = 0;
  l->qpack_stream_violation         = 0;
  l->wt_signal_mid_stream_violation = 0;
  l->flow_control_violation         = 0;
  l->transport_error                = 0;
  l->local_opened[0]                = 0;
  l->local_opened[1]                = 0;
  l->peer_stream_limit[0]           = 0;
  l->peer_stream_limit[1]           = 0;
  l->peer_wt_initial[0]             = 0;
  l->peer_wt_initial[1]             = 0;
  l->peer_wt_initial[2]             = 0;
}

/* Our own control stream plus the peer's. */
static void srvloop_init_ctrl(wired_srvloop* l) {
  l->ctrl_overflow     = 0;
  l->ctrl_settings_len = 0;
  l->ctrl.base         = 0;
  l->ctrl.len          = 0;
  l->ctrl.parsed       = 0;
  l->ctrl.open         = 0;
  l->ctrl.stream_id    = 0;
  l->h3peer            = (srvloop_h3peer){0}; /* push max 0 = h3_push_init */
  h3_control_init(&l->h3peer.ctrl);
}

int wired_srvloop_init(wired_srvloop* l, const u8* cli_scid, u8 cli_scid_len) {
  if (cli_scid_len > 20) {
    return 0;
  }
  wired_h3srv_state_init(&l->h3, DEFAULT_QPACK_MAX_TABLE_CAP);
  l->cli_scid_len = cli_scid_len;
  for (usz i = 0; i < cli_scid_len; i++) {
    l->cli_scid[i] = cli_scid[i];
  }
  srvloop_init_pn(l);
  srvloop_init_req(l);
  srvloop_init_ecn(l);
  srvloop_init_seen(l);
  srvloop_init_violation(l);
  srvloop_init_ctrl(l);
  pnspaces_recv_init(&l->ack_recv);
  ackpolicy_init(&l->app_ack_policy);
  ackpolicy_init(&l->ackst.hs_ack_policy);
  l->now_ms = 0;
  sentmeta_init(&l->ackst.sent);
  srvloop_streams_reset(l);
  srvloop_wt_streams_reset(l);
  /* also zeroes wt_uni_closed/uni_typed */
  srvloop_wt_uni_streams_reset(l);
  srvloop_pending_priority_reset(l);
  srvloop_rxacct_reset(l);
  return 1;
}

void wired_srvloop_set_handler(
    wired_srvloop* l, wired_srvloop_handler cb, void* ctx) {
  l->on_request = cb;
  l->req_ctx    = ctx;
}

/* The cumulative counter ecn (an RFC 3168 codepoint 0..3) advances, or 0 for
 * Not-ECT (nothing to count). Table-dispatched so wired_srvloop_ecn_note
 * stays a single branch regardless of how many codepoints are countable. */
u64* srvloop_ecn_counter_for(wired_srvloop* l, u8 ecn) {
  u64* table[4] = {0, &l->ecn_ect1, &l->ecn_ect0, &l->ecn_ce};
  return ecn < 4 ? table[ecn] : (u64*)0;
}

void wired_srvloop_ecn_note(wired_srvloop* l, u8 ecn) {
  u64* counter   = srvloop_ecn_counter_for(l, ecn);
  l->ackst.rx_ce = ecn == 3; /* RFC 3168 CE */
  if (counter) {
    (*counter)++;
  }
}
