#include "app/http3/server/srvrun/srvrun_impl.h"

/* draft-ietf-webtrans-http3-16 5.4: "For streams that were reset,
 * implementing WT_MAX_DATA requires that the QUIC stack provide the
 * WebTransport implementation with information about the final size of
 * streams" -- a client stream refused before its offer (srvrun_wtfc_reject)
 * is answered with RESET_STREAM + STOP_SENDING, and its Stream Body bytes
 * count against the session's data limit once the client's own FIN or
 * RESET_STREAM fixes its final size (RFC 9000 3.5/4.5). Until then it waits
 * here. */

static int srvrun_wtfc_pend_due(
    const srvrun_conn* c, const srvrun_wtfc_pend* e);
static void srvrun_wtfc_pend_count(srvrun_conn* c, srvrun_wtfc_pend* e);

/* Wait for stream id's final size, counting it against Session ID sid.
 * shortcut: with every entry waiting, the stream's bytes are never counted
 * -- the client's credit shrinks by them (never more is granted than it
 * sent); upgrade by sizing SRVRUN_WTFC_PEND to the refusals in flight. */
void srvrun_wtfc_pend_add(srvrun_conn* c, u64 id, u64 sid, usz hdr) {
  for (usz i = 0; i < SRVRUN_WTFC_PEND; i++) {
    srvrun_wtfc_pend* e = &c->wtx.pend[i];
    if (!e->used) {
      *e = (srvrun_wtfc_pend){id, sid, (u8)hdr, 1};
      return;
    }
  }
}

/* 1 iff e waits and its stream's final size is now known. */
static int srvrun_wtfc_pend_due(
    const srvrun_conn* c, const srvrun_wtfc_pend* e) {
  return e->used && wired_srvloop_rx_final_known(&c->l, e->id);
}

/* Count e's final size less its header against its session, if still open
 * (a final size the accounting already dropped counts 0, never more). */
static void srvrun_wtfc_pend_count(srvrun_conn* c, srvrun_wtfc_pend* e) {
  u64 seen = wired_srvloop_rx_extent(&c->l, e->id);
  int sidx = srvrun_wt_slot_by_connect_id(c, e->sid);
  e->used  = 0;
  if (sidx >= 0) {
    c->wtx.fc[sidx].done += seen - u64_min(seen, e->hdr);
  }
}

/* Per step: count every waiting stream whose final size arrived. */
void srvrun_wtfc_settle(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WTFC_PEND; i++) {
    if (srvrun_wtfc_pend_due(c, &c->wtx.pend[i])) {
      srvrun_wtfc_pend_count(c, &c->wtx.pend[i]);
    }
  }
}
