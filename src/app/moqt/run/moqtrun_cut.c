#include "app/moqt/run/moqtrun_impl.h"

/* draft-18 5.1: "A publisher SHOULD begin sending incomplete objects when
 * available." The relay's held fragment (moqtrun_relay_save_frag) stays
 * whole for decoding and the cache, but once its Object's header is in,
 * the bytes so far go out on every subscriber stream that would carry the
 * whole Object (moqtrun_cut_push); sub_part[i] counts what stream i got,
 * and the round completing the Object starts that far in
 * (moqtrun_cut_skip, moqtrun_cut_ring_take).
 *
 * Framing (tasks/loopeng/MoqtCutThrough.tla): a lossy stream may lose a
 * refused round only at an Object boundary; one refused partway into an
 * Object is reset instead (moqtrun_cut_refused) and late-opened again at
 * a later boundary. A ring-backed stream retries the same bytes. */

static int moqtrun_cut_head(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_relay* relay,
    moqdata_obj*               o);
static int moqtrun_cut_valid(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    moqctl_loc                 l,
    const moqdata_obj*         o);
static int moqtrun_cut_ready(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    const wired_moqtrun_relay* relay,
    moqctl_loc*                l);
static int moqtrun_cut_at_end(const moqtrel_sub* c, const moqtrel_buf* rb);
static int moqtrun_cut_ring_ok(
    const wired_moqt_hub* hub, const wired_moqtrun_relay* relay, usz i);
static int moqtrun_cut_stream_ok(
    const wired_moqtrun_sub* s, const wired_moqtrun_relay* relay, usz i);
static int moqtrun_cut_takes(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqctl_loc                 l);
static int moqtrun_cut_sub_ok(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_track* t,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqctl_loc                 l);
static int  moqtrun_cut_mid(const wired_moqtrun_relay* relay, usz i);
static void moqtrun_cut_ring_one(
    wired_moqtrun_relay* relay, moqtrel_buf* rb, usz i, u64 now_ms);
static void moqtrun_cut_push_one(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay,
    usz                        i);
static void moqtrun_cut_push_all(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay,
    moqctl_loc                 l);

/* Two chaining states at the same Object: the downstream chain (dseq)
 * still mirrors the publisher's. */
int moqtrun_cut_aligned(moqdata_objseq a, moqdata_objseq b) {
  return a.have_prev == b.have_prev && a.prev_id == b.prev_id;
}

/* 1 iff some sub slot was sent part of the held fragment's Object. */
int moqtrun_cut_any(const wired_moqtrun_relay* relay) {
  usz any = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    any |= relay->sub_part[i];
  }
  return any != 0;
}

/* The held fragment's Object header, whole (moqdata_obj_head_take). */
static int moqtrun_cut_head(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_relay* relay,
    moqdata_obj*               o) {
  return relay->frag_idx >= 0 && relay->frag_len != 0 &&
         moqdata_obj_head_take(
             wired_span_of(hub->frag_pool[relay->frag_idx], relay->frag_len), 0,
             relay->seq, o) == MOQDATA_OK;
}

/* Neither a Malformed Track (12.1), a Mandatory Object Property (2.5.1)
 * nor recorded nonexistent (draft-18 9.1): the whole Object will be
 * relayed as it is. */
static int moqtrun_cut_valid(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    moqctl_loc                 l,
    const moqdata_obj*         o) {
  return !moqtrun_obj_malformed(t, l) && !moqtrun_obj_mand(t, o->props) &&
         !moqtrun_obj_gone(hub, t, l);
}

/* The fragment's Object (at *l) can go out before it completes: its
 * header is in, the downstream chain still mirrors the publisher's (no
 * re-chained ID Delta pending), it is valid and not recorded
 * nonexistent (draft-18 9.1). */
static int moqtrun_cut_ready(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    const wired_moqtrun_relay* relay,
    moqctl_loc*                l) {
  moqdata_obj o = {0};
  if (!moqtrun_cut_head(hub, relay, &o) ||
      !moqtrun_cut_aligned(relay->dseq, relay->seq)) {
    return 0;
  }
  *l = moqctl_loc_of(relay->group_id, o.object_id);
  return moqtrun_cut_valid(hub, t, *l, &o);
}

/* Cursor c has sent every byte of its ring and has no re-framed start
 * pending: the fragment continues its stream exactly. */
static int moqtrun_cut_at_end(const moqtrel_sub* c, const moqtrel_buf* rb) {
  return c->sent == rb->tail && !c->lead_skip && !c->before_start;
}

static int moqtrun_cut_ring_ok(
    const wired_moqt_hub* hub, const wired_moqtrun_relay* relay, usz i) {
  if (relay->rel_idx < 0) {
    return 1;
  }
  const moqtrel_buf* rb = &hub->rel_pool[relay->rel_idx];
  return moqtrun_rel_sub_open(rb, i) && moqtrun_cut_at_end(&rb->subs[i], rb);
}

/* Sub slot i's relay stream is open and its first Object needs no
 * re-framing (sub_reframe: that one is sent whole). */
static int moqtrun_cut_stream_ok(
    const wired_moqtrun_sub* s, const wired_moqtrun_relay* relay, usz i) {
  return moqtrun_sub_gets_relay(s, relay) && relay->sub_stream_set[i] &&
         !(relay->sub_reframe >> i & 1);
}

/* Sub slot i (its stream open) is served, takes the Object at l and,
 * ring-backed, has caught up. */
static int moqtrun_cut_takes(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqctl_loc                 l) {
  return !moqtrun_relay_skips(&hub->peers[s->session_idx], relay, i) &&
         moqtrun_sub_gets_loc(s, l) && moqtrun_cut_ring_ok(hub, relay, i);
}

/* Sub slot i would get the whole Object at l on its open stream. */
static int moqtrun_cut_sub_ok(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_track* t,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqctl_loc                 l) {
  const wired_moqtrun_sub* s = &t->subs[i];
  return moqtrun_cut_stream_ok(s, relay, i) &&
         moqtrun_cut_takes(hub, s, relay, i, l);
}

/* Sub slot i's lossy stream is partway into an Object. */
static int moqtrun_cut_mid(const wired_moqtrun_relay* relay, usz i) {
  return relay->rel_idx < 0 && relay->sub_part[i] != 0;
}

/* A refused send on sub slot i's lossy stream partway into an Object:
 * dropping it would tear the Object, so the stream is reset (the
 * mid-Subgroup abort moqtrun_relay_shed_one uses) and late-opened again
 * at an Object boundary. A refused reset stops the slot for the
 * Subgroup instead: framed, if stalled. 1 when it applied. */
int moqtrun_cut_refused(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    usz                  i) {
  if (!moqtrun_cut_mid(relay, i)) {
    return 0;
  }
  if (hub->io.stream_reset(
          wt, relay->sub_stream_id[i], MOQTRUN_RESET_INTERNAL_ERROR) != 1) {
    relay->sub_expired |= moqtrun_sub_bit(i);
  }
  relay->sub_stream_set[i] = 0;
  relay->sub_part[i]       = 0;
  hub->stat_relay_reset++;
  return 1;
}

static void moqtrun_cut_push_one(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay,
    usz                        i) {
  wired_wt_session* wt   = hub->peers[t->subs[i].session_idx].wt;
  usz               part = relay->sub_part[i];
  wired_span        rest = wired_span_of(
      hub->frag_pool[relay->frag_idx] + part, relay->frag_len - part);
  if (rest.n == 0) {
    return;
  }
  if (hub->io.stream_send(wt, relay->sub_stream_id[i], rest, 0) == 1) {
    relay->sub_part[i] = relay->frag_len;
    return;
  }
  moqtrun_cut_refused(hub, wt, relay, i);
}

static void moqtrun_cut_push_all(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay,
    moqctl_loc                 l) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtrun_cut_sub_ok(hub, t, relay, i, l)) {
      moqtrun_cut_push_one(hub, t, relay, i);
    }
  }
}

/* The held fragment's new bytes to every stream that takes its Object. */
void moqtrun_cut_push(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* t,
    wired_moqtrun_relay*       relay) {
  moqctl_loc l;
  if (moqtrun_cut_ready(hub, t, relay, &l)) {
    moqtrun_cut_push_all(hub, t, relay, l);
  }
}

/* Sub slot i's share of a round, past what it was already sent of the
 * round's first Object. */
wired_span moqtrun_cut_skip(
    const wired_moqtrun_relay* relay, usz i, wired_span wire) {
  usz k = (usz)u64_min(relay->sub_part[i], wire.n);
  return wired_span_of(wire.p + k, wire.n - k);
}

/* A ring round completed the Object cursors were sent part of: each
 * such cursor moves past that part (its stream already carries it). */
static void moqtrun_cut_ring_one(
    wired_moqtrun_relay* relay, moqtrel_buf* rb, usz i, u64 now_ms) {
  if (relay->sub_part[i]) {
    moqtrel_note_sent(rb, (u32)i, relay->sub_part[i], now_ms);
  }
}

void moqtrun_cut_ring_take(
    wired_moqtrun_relay* relay, moqtrel_buf* rb, usz whole_n, u64 now_ms) {
  if (!whole_n) {
    return;
  }
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    moqtrun_cut_ring_one(relay, rb, i, now_ms);
  }
}

/* A round that completed the fragment's Object (whole_n bytes) ends
 * every partial send. */
void moqtrun_cut_settle(wired_moqtrun_relay* relay, usz whole_n) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    relay->sub_part[i] = whole_n ? 0 : relay->sub_part[i];
  }
}

/* The publisher's fin as the round forwards it: a FIN inside the held
 * Object is flagged (draft-19 11.4: FIN mid-Object) and, once part of
 * that Object went out, not forwarded (moqtrun_cut_torn). */
int moqtrun_cut_fin(wired_moqt_hub* hub, wired_moqtrun_relay* relay, int fin) {
  int torn = fin && relay->frag_len != 0;
  moqtrun_rx_flag(hub, torn);
  return fin && !moqtrun_cut_torn(hub, relay, torn);
}

/* A publisher FIN inside the held Object (torn) after part of it went
 * out: those streams cannot end framed, so the relay is poisoned and
 * every subscriber stream reset (moqtrun_relay_end_poisoned). 1 then. */
int moqtrun_cut_torn(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, int torn) {
  if (!torn || !moqtrun_cut_any(relay)) {
    return 0;
  }
  moqtrun_frag_release(relay);
  moqtrun_frag_drop(hub, relay, 1);
  return 1;
}
