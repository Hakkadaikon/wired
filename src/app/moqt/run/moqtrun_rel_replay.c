#include "app/moqt/run/moqtrun_impl.h"

/* After the opening moqtrun_relay_open_all: record each subscriber stream
 * that actually opened as a ring cursor at tail (the opening round carried
 * every byte so far). A slot that failed to open, or subscribes later,
 * rides this ring only through moqtrun_rel_late_attach_all -- i.e. only
 * while the ring still holds the stream right after its header. */
void moqtrun_rel_attach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay) {
  if (relay->rel_idx < 0) {
    return;
  }
  moqtrel_buf* rb = &hub->rel_pool[relay->rel_idx];
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    moqtrun_rel_attach_open(rb, track, relay, i, hub->live.last_now_ms);
  }
}

/* 1 while nothing past the SUBGROUP_HEADER was reclaimed (and a header
 * was saved): a late subscriber's stream can be the saved header followed
 * by the ring from offset hdr_len -- the whole stream, not a torn tail. */
int moqtrun_rel_holds_start(
    const wired_moqtrun_relay* relay, const moqtrel_buf* rb) {
  return relay->hdr_len != 0 && rb->head <= relay->hdr_len;
}

/* 1 for an active sub slot with neither a relay stream nor a cursor on
 * this ring (it became active after the relay started). A shed or
 * FIN'd cursor stays active, so it is never re-opened here. */
int moqtrun_rel_late_wanted(
    const wired_moqtrun_track* track,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb,
    usz                        i) {
  return moqtrun_sub_forwards(&track->subs[i]) && !relay->sub_stream_set[i] &&
         !rb->subs[i].active;
}

/* 1 iff relay's stream may be replayed to sub from the ring: sub takes
 * its Group, and the Objects past the saved header lie contiguous in
 * the ring (it never wrapped), so they can be read for sub's start and
 * End Objects (moqtrun_rel_replay).
 * ponytail: a wrapped ring (its tail past WIRED_MOQTREL_CAP while still
 * holding the header) is not replayed; read across the wrap if a late
 * subscriber ever needs that. */
int moqtrun_rel_replay_ok(
    const wired_moqtrun_sub*   sub,
    const wired_moqtrun_relay* relay,
    const moqtrel_buf*         rb) {
  return rb->tail <= WIRED_MOQTREL_CAP &&
         moqtrun_sub_wants_group(sub, relay->group_id);
}

/* Cursor c's next Object, at wire[off] chained from seq, goes out with its
 * absolute Object ID (draft-22 11.3.1): the first Object of a stream
 * that starts mid-Subgroup. Nothing when no Object is there. */
void moqtrun_rel_lead(
    moqtrel_sub* c, wired_span wire, usz off, moqdata_objseq seq) {
  usz         at = off, dl = off;
  u64         delta;
  moqdata_obj obj = {0};
  moqdata_obj_take(wire, &at, &seq, &obj);
  moqvi_take(wire, &dl, &delta);
  c->lead_id   = obj.object_id;
  c->lead_skip = (u32)(at != off) * (u32)(dl - off);
}

/* Cursor c's end once its subscriber's End Object falls inside wire, the
 * Objects at absolute offset base chained from seq: nothing past it is
 * sent (draft-22 3.3.1), and the lossy fallback skips slot i too. */
void moqtrun_rel_cut_end(
    wired_moqtrun_relay*     relay,
    moqtrel_sub*             c,
    const wired_moqtrun_sub* sub,
    usz                      i,
    wired_span               wire,
    moqdata_objseq           seq,
    u64                      base) {
  usz cut = moqtrun_wire_cutoff(sub, wire, 0, seq, relay->group_id);
  if (c->end || cut == wire.n) {
    return;
  }
  c->end = base + cut;
  relay->sub_expired |= moqtrun_sub_bit(i);
}

/* The Object decode state right after relay's saved SUBGROUP_HEADER. */
moqdata_objseq moqtrun_relay_hdr_seq(const wired_moqtrun_relay* relay) {
  usz off  = 0;
  u64 type = 0;
  moqvi_take(wired_span_of(relay->hdr, relay->hdr_len), &off, &type);
  return moqdata_objseq_of(type);
}

/* Opens sub slot i's stream for a replay starting at body[off]: the
 * saved header from the stream's first Object (off 0), else the late
 * head (moqtrun_relay_late_hdr) of one that starts mid-Subgroup. */
void moqtrun_rel_replay_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    usz                  off) {
  u8  hdr[WIRED_MOQTRUN_RELAY_HDR_MAX];
  usz n = relay->hdr_len;
  bytes_memcpy(hdr, relay->hdr, n);
  if (off) {
    n = moqtrun_relay_late_hdr(relay, hdr);
  }
  moqtrun_relay_open_one(hub, sub, relay, i, wired_span_of(hdr, n));
}

/* A just-attached replay cursor c starting at body[off] (chained from
 * seq; the End cut decodes from the state right after the header): its
 * first Object re-framed when the stream starts mid-Subgroup, its End
 * Object cut. */
void moqtrun_rel_replay_cuts(
    wired_moqtrun_relay*     relay,
    moqtrel_sub*             c,
    const wired_moqtrun_sub* sub,
    usz                      i,
    wired_span               body,
    usz                      off,
    moqdata_objseq           seq) {
  if (!c->active) {
    return;
  }
  if (off) {
    moqtrun_rel_lead(c, body, off, seq);
  }
  moqtrun_rel_cut_end(
      relay, c, sub, i, body, moqtrun_relay_hdr_seq(relay), relay->hdr_len);
}
