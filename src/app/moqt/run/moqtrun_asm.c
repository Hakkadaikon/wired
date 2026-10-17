#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_asm_over_cap(wired_span rest, usz* total);
static void moqtrun_ctl_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx);

/* Moves a's unread tail to the front, then appends as much of *data as
 * fits -- after discarding the bytes of an over-cap message still owed
 * (a->skip) -- and advances *data past everything consumed. */
void moqtrun_asm_push(wired_moqtrun_ctl_asm* a, wired_span* data) {
  usz drop = (usz)u64_min(a->skip, data->n);
  a->skip -= drop;
  moqtrun_span_drop(data, drop);
  usz keep = a->n - a->at;
  bytes_move_down(a->buf, a->buf + a->at, keep);
  usz take = (usz)u64_min(sizeof a->buf - keep, data->n);
  bytes_memcpy(a->buf + keep, data->p, take);
  a->n  = keep + take;
  a->at = 0;
  moqtrun_span_drop(data, take);
}

/* a's unread bytes. */
wired_span moqtrun_asm_rest(const wired_moqtrun_ctl_asm* a) {
  return wired_span_of(a->buf + a->at, a->n - a->at);
}

/* 1 iff rest starts with a complete header whose Length exceeds the cap;
 * *total is then the whole message's size. */
static int moqtrun_asm_over_cap(wired_span rest, usz* total) {
  usz at = 0;
  u64 type;
  u16 len;
  if (moqctl_peek_header(rest, &at, &type, &len) != MOQCTL_OK) {
    return 0;
  }
  *total = at + len;
  return len > WIRED_MOQTRUN_CTL_MSG_MAX;
}

/* Next complete message held in a (moqctl_peek_type's result, *body a view
 * into a->buf valid until the next push), or MOQCTL_INSUFFICIENT when more
 * bytes are needed. A message whose Length exceeds
 * WIRED_MOQTRUN_CTL_MSG_MAX is consumed by its Length, now and across
 * later deliveries (a->skip), and reported as MOQTRUN_ASM_OVER_CAP
 * (moqtrun_dispatch_over_cap). */
int moqtrun_asm_pop(wired_moqtrun_ctl_asm* a, u64* type, wired_span* body) {
  if (a->skip) {
    return MOQCTL_INSUFFICIENT; /* rest of a held message */
  }
  wired_span rest  = moqtrun_asm_rest(a);
  usz        total = 0;
  if (moqtrun_asm_over_cap(rest, &total)) {
    usz held = (usz)u64_min(total, rest.n);
    a->at += held;
    a->skip = total - held;
    return MOQTRUN_ASM_OVER_CAP;
  }
  usz off = 0;
  int r   = moqctl_peek_type(rest, &off, type, body);
  a->at += off;
  return r;
}

/* Routes every complete message the handled stream's reassembly holds. */
static void moqtrun_ctl_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  u64        type = 0;
  wired_span body = {0, 0};
  int        r;
  while ((r = moqtrun_asm_pop(moqtrun_cur_asm(p), &type, &body)) !=
         MOQCTL_INSUFFICIENT) {
    moqtrun_msg_route(p, r, type, body)(hub, p, peer_idx, body);
  }
}

/* Dispatches every complete control message found in data on the stream
 * p is handling (p->req, else the control stream), prefixed by the
 * incomplete tail the previous call left in that stream's reassembly -- a
 * message may arrive split across calls. peer_idx is
 * passed through for handlers that need to record which session a subscription
 * belongs to. Every handler queues its reply (moqtrun_queue_reply) rather than
 * sending it immediately.
 *
 * Flushes at BOTH ends: the leading flush retries whatever an earlier
 * dispatch could not send yet (moqtrun_flush_replies' own doc -- a
 * keep-open bidi stream's previous round must be acknowledged before a new
 * one is accepted, and that can still be pending when the next dispatch
 * starts), and the trailing flush sends this dispatch's own new replies.
 * Two calls, never more, keeps every reply either delivered or still
 * queued for the next try -- never dropped. */
void moqtrun_dispatch_ctl_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span data) {
  moqtrun_flush_cur(&hub->io, p);
  do {
    moqtrun_asm_push(moqtrun_cur_asm(p), &data);
    moqtrun_ctl_drain(hub, p, peer_idx);
  } while (data.n > 0);
  moqtrun_flush_cur(&hub->io, p);
}

usz wired_moqt_publish_blob(
    wired_moqt_hub* hub,
    wired_span      name,
    u64             track_alias,
    wired_span      blob,
    wired_mspan     wire) {
  if (moqtrun_key_oversized(moqtrun_key_name(name))) {
    return 0;
  }
  usz n = moqdata_blob_build(wire, track_alias, blob);
  if (n == 0) {
    return 0;
  }
  moqtrun_track_claim(
      hub, &hub->blob_track, moqtrun_key_name(name), track_alias);
  hub->blob_wire = wired_span_of(wire.p, n);
  moqdata_objseq seq;
  u64            group;
  moqtrun_subgroup_scan(hub->blob_wire, &hub->blob_track, &seq, &group);
  return n;
}
