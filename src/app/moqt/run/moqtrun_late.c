#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_late_open_skip(const wired_moqtrun_relay* relay, int fin);
static int moqtrun_round_void(wired_span wire, int fin);

/* 1 iff a late open would be pointless: the round at hand already ends the
 * stream (opening one just to close it delivers nothing), or no header was
 * saved to open it with. */
static int moqtrun_late_open_skip(const wired_moqtrun_relay* relay, int fin) {
  return fin || relay->hdr_len == 0;
}

/* A subscriber that joined AFTER this relay started (its slot never
 * opened): open its stream now, carrying the saved SUBGROUP_HEADER bytes
 * alone -- the current round's Objects are dropped for this late joiner
 * (voice is loss-tolerant; the next round appends normally, and the
 * header-only first chunk is a well-formed stream head for the client's
 * incremental decoder). The stream starts mid-subgroup, so FIRST_OBJECT
 * (0x40) is cleared (draft-22 2.2 / 11.3.1), and a mode-0b01 Subgroup ID
 * is spelled out (mode 0b10): the stream's first Object is no longer the
 * Subgroup's. Its first Object is re-framed when sent (sub_reframe). */
usz moqtrun_relay_late_hdr(const wired_moqtrun_relay* relay, u8* out) {
  moqdata_subhdr h;
  usz            off = 0;
  moqdata_subhdr_take(wired_span_of(relay->hdr, relay->hdr_len), &off, &h);
  return moqtrun_late_hdr_of(h, relay->subgroup_id, out);
}

void moqtrun_relay_late_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    int                  fin) {
  if (moqtrun_late_open_skip(relay, fin)) return;
  u8  hdr[WIRED_MOQTRUN_RELAY_HDR_MAX];
  usz n = moqtrun_relay_late_hdr(relay, hdr);
  moqtrun_relay_open_one(hub, sub, relay, i, wired_span_of(hdr, n));
  relay->sub_reframe |= (u32)(relay->sub_stream_set[i] != 0) << i;
}

/* 1 iff a round has nothing to send: every Object was cut before the
 * subscriber's start Object and the stream goes on. */
static int moqtrun_round_void(wired_span wire, int fin) {
  return wire.n == 0 && !fin;
}

/* Forward to sub slot i's open stream, or -- for a subscriber whose
 * stream was never opened (it subscribed after the relay started) -- open
 * one now (moqtrun_relay_late_open). */
void moqtrun_relay_deliver_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r) {
  if (relay->sub_stream_set[i]) {
    if (!moqtrun_round_void(r.wire, r.fin))
      moqtrun_relay_forward_one(hub, dst->wt, sub, relay, i, r);
    return;
  }
  moqtrun_relay_late_open(hub, sub, relay, i, r.fin);
}

u32 moqtrun_sub_bit(usz i) { return (u32)1 << i; }

/* Sub slot i's stream on relay was reset for DELIVERY_TIMEOUT: counted,
 * and never reopened for this Subgroup. */
void moqtrun_note_expired(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz i) {
  relay->sub_expired |= moqtrun_sub_bit(i);
  hub->stat_timeout_reset++;
}

/* Sub slot i is not served on relay: its peer left, or its stream timed
 * out for this Subgroup. */
int moqtrun_relay_skips(
    const wired_moqtrun_peer* dst, const wired_moqtrun_relay* relay, usz i) {
  return !dst->in_use || (relay->sub_expired & moqtrun_sub_bit(i));
}

/* draft 8: the round's oldest Object reached the hub at born_ms; past
 * sub's OBJECT_DELIVERY_TIMEOUT its stream is reset with DELIVERY_TIMEOUT
 * and not reopened for this Subgroup. 1 when it expired. */
int moqtrun_relay_expire(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_peer*      dst,
    wired_moqtrun_relay*     relay,
    usz                      i,
    u64                      born_ms) {
  if (!moqtrun_sub_late(sub, hub->live.last_now_ms - born_ms)) return 0;
  if (relay->sub_stream_set[i]) {
    hub->io.stream_reset(
        dst->wt, relay->sub_stream_id[i], MOQTRUN_RESET_DELIVERY_TIMEOUT);
    moqtss_note_shed(hub, dst->wt); /* SSTS (moqtssts_run.c): congestion */
  }
  relay->sub_stream_set[i] = 0;
  moqtrun_note_expired(hub, relay, i);
  return 1;
}
