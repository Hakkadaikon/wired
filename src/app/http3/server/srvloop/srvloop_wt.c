#include "app/http3/server/srvloop/srvloop_impl.h"

/* Reset a WT slot's receive window: no bytes seen yet, base at the stream's
 * own start (post-signal/type-varint coordinate 0). */
void srvloop_wt_window_reset(wired_srvloop_wt_window* w) {
  w->base     = 0;
  w->range_n  = 0;
  w->frontier = 0;
}

/* Mark every WT bidi stream reassembly slot free (draft-ietf-webtrans-http3-15
 * 4.3), mirroring srvloop_streams_reset above for the separate wt_streams
 * table. */
void srvloop_wt_streams_reset(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    l->wt_streams[i].in_use            = 0;
    l->wt_streams[i].stream_id         = 0;
    l->wt_streams[i].sig_len           = 0;
    l->wt_streams[i].fin               = 0;
    l->wt_streams[i].fin_off           = 0;
    l->wt_streams[i].offered           = 0;
    l->wt_streams[i].delivered_len     = 0;
    l->wt_streams[i].fin_delivered     = 0;
    l->wt_streams[i].credit_advertised = 0;
    l->wt_streams[i].credit_hold       = 0;
    srvloop_wt_window_reset(&l->wt_streams[i].win);
  }
}

/* Mark every WT uni stream reassembly slot free (draft-ietf-webtrans-http3-15
 * 4.3), mirroring srvloop_wt_streams_reset above for the separate
 * wt_uni_streams table. */
void srvloop_wt_uni_streams_reset(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    l->wt_uni_streams[i].in_use            = 0;
    l->wt_uni_streams[i].stream_id         = 0;
    l->wt_uni_streams[i].type_len          = 0;
    l->wt_uni_streams[i].fin               = 0;
    l->wt_uni_streams[i].fin_off           = 0;
    l->wt_uni_streams[i].offered           = 0;
    l->wt_uni_streams[i].delivered_len     = 0;
    l->wt_uni_streams[i].fin_delivered     = 0;
    l->wt_uni_streams[i].credit_advertised = 0;
    l->wt_uni_streams[i].credit_hold       = 0;
    srvloop_wt_window_reset(&l->wt_uni_streams[i].win);
  }
  bytes_memset(&l->wt_uni_closed, 0, sizeof l->wt_uni_closed);
  bytes_memset(&l->uni_typed, 0, sizeof l->uni_typed);
}
