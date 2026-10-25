#include "app/http3/server/srvloop/srvloop_impl.h"
#include "common/diag/error/error.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* RFC 9000 4.1 / 4.5: the frame side of the receive accounting. Each
 * stream's highest offset feeds the connection-level byte count checked
 * against MAX_DATA; a FIN or RESET_STREAM fixes its final size, and data
 * past it or a different one is a FINAL_SIZE_ERROR. */

typedef u64 (*rxacct_fn)(wired_srvloop* l, const framewalk_item* fr);

static u64 rxacct_grow(
    wired_srvloop* l, wired_srvloop_rxacct* e, u64 off, u64 len);
static u64 rxacct_fin(wired_srvloop_rxacct* e, const stream_frame* sf);
static u64 rxacct_stream(wired_srvloop* l, const framewalk_item* fr);
static u64 rxacct_reset(wired_srvloop* l, const framewalk_item* fr);
static u64 rxacct_frame(wired_srvloop* l, const framewalk_item* fr);
static u64 rxacct_conn_error(const wired_srvloop* l);

/* RFC 9000 4.5: [off, off+len) received; the stream's growth counts toward
 * the connection's bytes. */
static u64 rxacct_grow(
    wired_srvloop* l, wired_srvloop_rxacct* e, u64 off, u64 len) {
  u64 before = e->fs.highest;
  int ok     = finalsize_data(&e->fs, off, len);
  l->rx_conn_bytes += e->fs.highest - before;
  return ok ? 0 : ERR_FINAL_SIZE_ERROR;
}

/* RFC 9000 4.5: a FIN fixes the final size; one that changes it, or lands
 * below data already received, is a FINAL_SIZE_ERROR. */
static u64 rxacct_fin(wired_srvloop_rxacct* e, const stream_frame* sf) {
  return sf->fin && !finalsize_set(&e->fs, sf->offset + sf->length)
             ? ERR_FINAL_SIZE_ERROR
             : 0;
}

static u64 rxacct_stream(wired_srvloop* l, const framewalk_item* fr) {
  stream_frame          sf;
  wired_srvloop_rxacct* e;
  frame_get_stream(fr->start, fr->remaining, &sf);
  e = srvloop_rxacct_entry(l, sf.stream_id);
  if (!e) {
    return 0;
  }
  if (rxacct_grow(l, e, sf.offset, sf.length)) {
    return ERR_FINAL_SIZE_ERROR;
  }
  return rxacct_fin(e, &sf);
}

/* RFC 9000 4.5 / 19.4: RESET_STREAM's Final Size must match a known one and
 * cover every byte received; every byte up to it counts toward the
 * connection's bytes, sent or not. */
static u64 rxacct_reset(wired_srvloop* l, const framewalk_item* fr) {
  reset_stream_frame    rs;
  wired_srvloop_rxacct* e;
  reset_stream_decode(fr->start, fr->remaining, &rs);
  e = srvloop_rxacct_entry(l, rs.stream_id);
  if (!e) {
    return 0;
  }
  if (!finalsize_set(&e->fs, rs.final_size)) {
    return ERR_FINAL_SIZE_ERROR;
  }
  return rxacct_grow(l, e, rs.final_size, 0);
}

/* The frame kinds that carry stream bytes or a final size. */
static const rxacct_fn RXACCT_BY_KIND[FK_RESET_STREAM_AT + 1] = {
    [FK_STREAM]       = rxacct_stream,
    [FK_RESET_STREAM] = rxacct_reset,
};

static u64 rxacct_frame(wired_srvloop* l, const framewalk_item* fr) {
  rxacct_fn fn = RXACCT_BY_KIND[frame_classify(fr->type)];
  return fn ? fn(l, fr) : 0;
}

/* RFC 9000 4.1: "MUST close the connection with an error of type
 * FLOW_CONTROL_ERROR if the sender violates the advertised connection ...
 * data limits". */
static u64 rxacct_conn_error(const wired_srvloop* l) {
  return l->rx_max_data && l->rx_conn_bytes > l->rx_max_data
             ? ERR_FLOW_CONTROL_ERROR
             : 0;
}

/* Account every stream frame of an already validated payload (every frame
 * measured, so each decode succeeds); returns the first error, 0 if none. */
u64 srvloop_rxacct_payload(wired_srvloop* l, wired_span pl) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, pl.p, pl.n);
  while (framewalk_next(&it, &fr)) {
    u64 e = rxacct_frame(l, &fr);
    if (e) {
      return e;
    }
  }
  return rxacct_conn_error(l);
}
