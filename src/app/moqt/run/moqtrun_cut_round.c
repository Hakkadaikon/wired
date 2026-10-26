#include "app/moqt/run/moqtrun_impl.h"

/* The round side of relay cut-through (moqtrun_cut.c): a round past what
 * each stream was already sent, refusals that would tear an Object, the
 * ring's cursors moved past a pushed part, and a FIN inside one. */

static int  moqtrun_cut_mid(const wired_moqtrun_relay* relay, usz i);
static void moqtrun_cut_ring_one(
    wired_moqtrun_relay* relay, moqtrel_buf* rb, usz i, u64 now_ms);

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
