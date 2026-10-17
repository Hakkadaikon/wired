#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_pre_is(const wired_moqtrun_peer* p, u64 sid);
static void moqtrun_pre_rest(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    usz                 skip,
    int                 fin);
static wired_moqtrun_peer* moqtrun_peer_of_ctx(
    wired_moqt_hub* hub, wired_wt_session* s);
static int moqtrun_prop_is_timeout(u64 type);

static int moqtrun_pre_is(const wired_moqtrun_peer* p, u64 sid) {
  return p->pre_n != 0 && p->pre_sid == sid;
}

/* data's bytes past the first skip, routed like any later delivery (an
 * empty, FIN-less remainder is nothing to route). */
static void moqtrun_pre_rest(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    usz                 skip,
    int                 fin) {
  if (skip == data.n && !fin) {
    return;
  }
  moqtrun_rx_route(
      hub, p, sid, wired_span_of(data.p + skip, data.n - skip), fin);
}

/* The next delivery of the stream moqtrun_pre_stash kept: the kept bytes
 * plus data's head complete the first varint, which then dispatches as
 * the stream's first delivery (classified whole), and data's rest
 * follows. Still short: kept again (or, with FIN, dropped -- a stream
 * cut inside its Type is no stream at all). */
void moqtrun_pre_feed(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  u8  v[sizeof p->pre];
  u64 t;
  usz had = p->pre_n;
  usz k   = (usz)u64_min(sizeof v - had, data.n);
  bytes_memcpy(v, p->pre, had);
  bytes_memcpy(v + had, data.p, k);
  usz used = moqvi_decode(v, had + k, &t);
  p->pre_n = 0;
  if (!used) {
    moqtrun_pre_stash(p, sid, wired_span_of(v, had + k), fin);
    return;
  }
  moqtrun_dispatch_other(hub, p, sid, wired_span_of(v, used), 0);
  moqtrun_pre_rest(hub, p, sid, data, used - had, fin);
}

/* A held delivery replayed: a stream whose first varint replay left
 * kept (moqtrun_pre_stash) continues through moqtrun_pre_feed. */
void moqtrun_dispatch_held(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_pre_is(p, stream_id)) {
    moqtrun_pre_feed(hub, p, stream_id, data, fin);
  } else {
    moqtrun_dispatch_other(hub, p, stream_id, data, fin);
  }
}

/* s's peer in hub, 0 for an unknown session or a NULL hub. */
static wired_moqtrun_peer* moqtrun_peer_of_ctx(
    wired_moqt_hub* hub, wired_wt_session* s) {
  return hub ? moqtrun_find_by_wt(hub, s) : 0;
}

void wired_moqt_on_stream_data(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    wired_span        data,
    int               fin) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_peer_of_ctx(hub, s);
  if (!p) {
    return;
  }
  if (moqtrun_pre_is(p, stream_id)) {
    moqtrun_pre_feed(hub, p, stream_id, data, fin);
  } else {
    moqtrun_rx_route(hub, p, stream_id, data, fin);
  }
  moqtrun_hold_replay(hub, p);
  moqtrun_pubdone_sweep(hub);
}

/* ===================== OBJECT_DATAGRAM relay (draft 11.3) ============= */

/* The datagram plane is usable for this delivery: the sending session is
 * registered AND the io table actually has a send_datagram entry (0 in an
 * older positional initializer -- must never be dereferenced). */
int moqtrun_dg_ready(const wired_moqt_hub* hub, const void* p) {
  return p != 0 && hub->io.send_datagram != 0;
}

int moqtrun_kvp_next(wired_span props, usz* off, u64* prev, moqkvp* kv) {
  return *off < props.n && moqkvp_take(props, off, prev, kv) == MOQKVP_OK;
}

static int moqtrun_prop_is_timeout(u64 type) {
  return type == MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT ||
         type == MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT;
}

/* 1 iff props hold an OBJECT/SUBGROUP_DELIVERY_TIMEOUT Property (18
 * 12.1/12.2 types 0x02/0x06). */
int moqtrun_props_have_timeout(wired_span props) {
  usz    off  = 0;
  u64    prev = 0;
  moqkvp kv;
  while (moqtrun_kvp_next(props, &off, &prev, &kv)) {
    if (moqtrun_prop_is_timeout(kv.type)) {
      return 1;
    }
  }
  return 0;
}
