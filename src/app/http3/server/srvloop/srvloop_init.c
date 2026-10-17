#include "app/http3/server/srvloop/srvloop_impl.h"

/* RFC 9218 10 / 9218-010: mark every buffered PRIORITY_UPDATE slot free. */
void srvloop_pending_priority_reset(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_PENDING_PRIORITY; i++)
    l->pending_priority[i].in_use = 0;
}

/* Packet-number spaces and handshake progress. */
void srvloop_init_pn(wired_srvloop* l) {
  l->tx_pn          = 0;
  l->hs_tx_pn       = 0;
  l->app_rx_pn      = 0;
  l->app_rx_hi      = 0;
  l->app_rx_seen    = 0;
  l->np_hi          = 0;
  l->np_seen        = 0;
  l->step_np_new    = 0;
  l->drop_newer     = 0;
  l->ncid_rx_n      = 0;
  l->ncid_malformed = 0;
  l->hs_rx_pn       = 0;
  l->hs_rx_hi       = 0;
  l->hs_rx_seen     = 0;
  l->hs_done_sent   = 0;
  l->ticket_sent    = 0;
}

/* Request dispatch and per-request stream bookkeeping. */
void srvloop_init_req(wired_srvloop* l) {
  l->on_request          = 0;
  l->req_ctx             = 0;
  l->got_request         = 0;
  l->peer_closed         = 0;
  l->resp_external       = 0;
  l->peer_reset_n        = 0;
  l->peer_reset_count    = 0;
  l->req_next_id         = 0;
  l->on_body             = 0;
  l->on_body_abort       = 0;
  l->req_frame_error     = 0;
  l->req_body_released   = 0;
  l->wt_refused_n        = 0;
  l->wt_refused_overflow = 0;
}

/* ACK/ECN feedback and the received-codepoint counters. */
void srvloop_init_ecn(wired_srvloop* l) {
  l->ack_n           = 0;
  l->ecn_ack_seen    = 0;
  l->ecn_ack_largest = 0;
  l->ecn_ack_ect0    = 0;
  l->ecn_ack_ect1    = 0;
  l->ecn_ack_ce      = 0;
  l->ecn_ect0        = 0;
  l->ecn_ect1        = 0;
  l->ecn_ce          = 0;
}

/* Peer frames seen. max_data_seen_flag/streams_blocked_seen_flag/
 * path_response_seen_flag are "not reset across steps by this loop itself"
 * (see their own doc in srvloop.h) -- but that convention only holds once
 * a step has actually run and left a real 0/1 in them; init is where they
 * get their FIRST defined value, or a caller that builds a wired_srvloop by
 * struct-copy from an uninitialized local (as tests do) inherits whatever
 * garbage bit pattern was on the stack, e.g. reading
 * streams_blocked_seen_flag as nonzero and spuriously sending an
 * unrequested MAX_STREAMS. */
void srvloop_init_seen(wired_srvloop* l) {
  l->rx_datagram_n                 = 0;
  l->we_advertised_max_datagram    = 0;
  l->closed_stream_id              = 0;
  l->closed_stream_seen            = 0;
  l->max_data_seen                 = 0;
  l->max_data_seen_flag            = 0;
  l->max_stream_data_n             = 0;
  l->streams_blocked_seen_flag     = 0;
  l->streams_blocked_uni_seen_flag = 0;
  l->max_streams_uni_seen          = 0;
  l->max_streams_uni_seen_flag     = 0;
  l->path_response_seen_flag       = 0;
}
