#include "transport/conn/loop/connrunner/send.h"

#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/recovery/rtx/rtxdrive/build.h"
#include "transport/recovery/rtx/sentmeta/detect_loss.h"

/* Any ack-eliciting packet sitting in the receive queue (RFC 9000 13.2.1). */
static int queue_has_eliciting(const connrunner* r) {
  usz i;
  for (i = 0; i < r->loop.rx_n; i++)
    if (r->loop.rx[i].ack_eliciting) return 1;
  return 0;
}

/* RFC 9000 13.2.1: the upcoming step drains the queued receives before the send
 * decision, so an ACK will be owed if one already is or any queued receive is
 * ack-eliciting. Predicting it here lets the flush match the step's choice. */
static int will_owe_ack(const connrunner* r) {
  return r->loop.ack_owed || queue_has_eliciting(r);
}

/* RFC 9000 13.2.1 / RFC 9002 6: the loop's send priority is an owed ACK, then a
 * retransmission, then new data. pending_kind reads that order off the loop's
 * pre-step state (with the receive queue folded in) so the flush builds the
 * same packet the loop chose. */
int connrunner_pending_kind(const connrunner* r) {
  int present[4];
  int kind;
  present[1] = will_owe_ack(r);
  present[2] = r->loop.rtx_n > 0;
  present[3] = r->loop.have_new_data;
  for (kind = 1; kind <= 3; kind++)
    if (present[kind]) return kind;
  return 0;
}

/* RFC 9000 19.3: an ACK acknowledging up to the highest received packet number
 * in the send level's space. The space's next expected number is rx, so the
 * largest seen is rx-1 (RFC 9000 12.3: spaces are acknowledged independently).
 */
static usz cr_build_ack(const connrunner* r, wired_obuf* out) {
  ack_frame f  = {0};
  u64       rx = connio_rx_next(&r->io, r->loop.level);
  if (rx == 0) return 0; /* nothing received to acknowledge */
  f.n_ranges     = 1;
  f.ranges[0].hi = rx - 1;
  f.ranges[0].lo = rx - 1;
  return ack_encode(out->p, out->cap, &f);
}

/* RFC 9000 19.7: a minimal ack-eliciting payload stands in for new application
 * data, and for a retransmission whose original bytes the store no longer
 * holds. */
static usz cr_build_ping(wired_obuf* out) {
  return frame_put_simple(out->p, out->cap, FRAME_PING);
}

void connrunner_capture_rtx(connrunner* r) {
  r->rtx_held = r->loop.rtx_n > 0;
  if (r->rtx_held) r->rtx_pn = r->loop.rtx[0].pn;
}

/* RFC 9002 13.3: re-send the lost packet's actual frame bytes under the new
 * packet number. Falls back to a PING stand-in when no lost pn was captured or
 * its bytes are not held. */
static usz cr_build_rtx(const connrunner* r, wired_obuf* out) {
  if (r->rtx_held) rtxdrive_build(&r->rtx, r->rtx_pn, out);
  return out->len ? out->len : cr_build_ping(out);
}

/* Build the frame bytes for kinds 2/3 (retransmission / new-data stand-in);
 * kind 0 is handled before this is reached. */
static usz cr_build_data(const connrunner* r, int kind, wired_obuf* out) {
  if (kind == 2) return cr_build_rtx(r, out);
  return cr_build_ping(out); /* new data */
}

/* Build the frame bytes for the chosen kind into out (1=ACK, 2=retransmission,
 * 3=new-data stand-in, 0=nothing). Returns the length. */
static usz cr_build_frames(const connrunner* r, int kind, wired_obuf* out) {
  if (kind == 1) return cr_build_ack(r, out);
  if (kind == 0) return 0;
  return cr_build_data(r, kind, out);
}

usz connrunner_flush_sends(connrunner* r, u64 sent_before, int kind) {
  u8         frames[64];
  usz        fl;
  wired_obuf fb = obuf_of(frames, sizeof(frames));
  if (r->loop.next_pn == sent_before) return 0; /* loop sent nothing */
  fl = cr_build_frames(r, kind, &fb);
  if (fl == 0) return 0;
  {
    connio_send_in sin = {r->loop.level, wired_span_of(frames, fl)};
    wired_obuf     ob  = obuf_of(r->txbuf, sizeof(r->txbuf));
    return connio_send(&r->io, &sin, &ob);
  }
}

/* RFC 9002 2 / 13.2.1: an ACK-only packet (kind 1) is neither ack-eliciting nor
 * counted in flight; a retransmission or new data (kind 2/3) is both. */
static int kind_in_flight(int kind) { return kind >= 2; }

void connrunner_track_sent(connrunner* r, const connrunner_sent_in* in) {
  int infl;
  if (in->sent_len == 0) return;
  infl = kind_in_flight(in->kind);
  {
    sentmeta_out pkt = {
        connio_tx_next(&r->io, r->loop.level) - 1, in->now, infl, infl,
        in->sent_len};
    sentmeta_on_sent(&r->sent, &pkt);
  }
}

/* ponytail: no RTT estimator is wired into this loop yet, so time-threshold
 * loss (RFC 9002 6.1.2) has no loss_delay to use; pass an effectively infinite
 * delay so detection relies purely on the packet threshold (6.1.1). When an RTT
 * estimate lands, replace this with max(SRTT, latest)*9/8 (kTimeThreshold). */
#define CONNRUNNER_NO_RTT_DELAY (1ull << 62)

/* Feed the oldest sentmeta-lost pn into the resend slot only when the loop
 * captured none of its own (RFC 9002 13.3). */
static int take_lost(const connrunner* r, usz n) {
  return n > 0 && !r->rtx_held;
}

void connrunner_track_loss_ex(connrunner* r, u64 now, u64* lost, usz* n) {
  *n = 0;
  if (!r->io.disp.has_ack)
    return; /* largest_acked is only valid after an ACK */
  sentmeta_loss_in in = {
      r->io.disp.largest_acked, now, CONNRUNNER_NO_RTT_DELAY};
  sentmeta_detect_loss(&r->sent, &in, (sentmeta_u64out){lost, n});
  if (take_lost(r, *n)) r->rtx_pn = lost[0], r->rtx_held = 1;
}

void connrunner_track_loss(connrunner* r, u64 now) {
  u64 lost[SENTMETA_CAP];
  usz n;
  connrunner_track_loss_ex(r, now, lost, &n);
}
