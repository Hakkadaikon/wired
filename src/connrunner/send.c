#include "connrunner/send.h"
#include "frame/ack.h"
#include "frame/frame.h"
#include "rtxdrive/build.h"
#include "sentmeta/detect_loss.h"

/* Any ack-eliciting packet sitting in the receive queue (RFC 9000 13.2.1). */
static int queue_has_eliciting(const quic_connrunner *r)
{
    usz i;
    for (i = 0; i < r->loop.rx_n; i++)
        if (r->loop.rx[i].ack_eliciting) return 1;
    return 0;
}

/* RFC 9000 13.2.1: the upcoming step drains the queued receives before the send
 * decision, so an ACK will be owed if one already is or any queued receive is
 * ack-eliciting. Predicting it here lets the flush match the step's choice. */
static int will_owe_ack(const quic_connrunner *r)
{
    return r->loop.ack_owed || queue_has_eliciting(r);
}

/* RFC 9000 13.2.1 / RFC 9002 6: the loop's send priority is an owed ACK, then a
 * retransmission, then new data. pending_kind reads that order off the loop's
 * pre-step state (with the receive queue folded in) so the flush builds the
 * same packet the loop chose. */
int quic_connrunner_pending_kind(const quic_connrunner *r)
{
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
 * largest seen is rx-1 (RFC 9000 12.3: spaces are acknowledged independently). */
static usz cr_build_ack(const quic_connrunner *r, u8 *buf, usz cap)
{
    quic_ack_frame f = {0};
    u64 rx = quic_connio_rx_next(&r->io, r->loop.level);
    if (rx == 0) return 0; /* nothing received to acknowledge */
    f.n_ranges = 1;
    f.ranges[0].hi = rx - 1;
    f.ranges[0].lo = rx - 1;
    return quic_ack_encode(buf, cap, &f);
}

/* RFC 9000 19.7: a minimal ack-eliciting payload stands in for new application
 * data, and for a retransmission whose original bytes the store no longer
 * holds. */
static usz cr_build_ping(u8 *buf, usz cap)
{
    return quic_frame_put_simple(buf, cap, QUIC_FRAME_PING);
}

void quic_connrunner_capture_rtx(quic_connrunner *r)
{
    r->rtx_held = r->loop.rtx_n > 0;
    if (r->rtx_held) r->rtx_pn = r->loop.rtx[0].pn;
}

/* RFC 9002 13.3: re-send the lost packet's actual frame bytes under the new
 * packet number. Falls back to a PING stand-in when no lost pn was captured or
 * its bytes are not held. */
static usz cr_build_rtx(const quic_connrunner *r, u8 *buf, usz cap)
{
    usz len = 0;
    if (r->rtx_held)
        quic_rtxdrive_build(&r->rtx, r->rtx_pn, buf, cap, &len);
    return len ? len : cr_build_ping(buf, cap);
}

/* Build the frame bytes for kinds 2/3 (retransmission / new-data stand-in);
 * kind 0 is handled before this is reached. */
static usz cr_build_data(const quic_connrunner *r, int kind, u8 *buf, usz cap)
{
    if (kind == 2) return cr_build_rtx(r, buf, cap);
    return cr_build_ping(buf, cap); /* new data */
}

/* Build the frame bytes for the chosen kind into buf (1=ACK, 2=retransmission,
 * 3=new-data stand-in, 0=nothing). Returns the length. */
static usz cr_build_frames(const quic_connrunner *r, int kind, u8 *buf, usz cap)
{
    if (kind == 1) return cr_build_ack(r, buf, cap);
    if (kind == 0) return 0;
    return cr_build_data(r, kind, buf, cap);
}

usz quic_connrunner_flush_sends(quic_connrunner *r, u64 sent_before, int kind)
{
    u8 frames[64];
    usz fl;
    if (r->loop.next_pn == sent_before) return 0; /* loop sent nothing */
    fl = cr_build_frames(r, kind, frames, sizeof(frames));
    if (fl == 0) return 0;
    return quic_connio_send(&r->io, r->loop.level, frames, fl,
                            r->txbuf, sizeof(r->txbuf));
}

/* RFC 9002 2 / 13.2.1: an ACK-only packet (kind 1) is neither ack-eliciting nor
 * counted in flight; a retransmission or new data (kind 2/3) is both. */
static int kind_in_flight(int kind) { return kind >= 2; }

void quic_connrunner_track_sent(quic_connrunner *r, u64 now, int kind,
                                usz sent_len)
{
    int infl;
    if (sent_len == 0) return;
    infl = kind_in_flight(kind);
    quic_sentmeta_on_sent(&r->sent, quic_connio_tx_next(&r->io, r->loop.level) - 1,
                          now, infl, infl, sent_len);
}

/* ponytail: no RTT estimator is wired into this loop yet, so time-threshold
 * loss (RFC 9002 6.1.2) has no loss_delay to use; pass an effectively infinite
 * delay so detection relies purely on the packet threshold (6.1.1). When an RTT
 * estimate lands, replace this with max(SRTT, latest)*9/8 (kTimeThreshold). */
#define QUIC_CONNRUNNER_NO_RTT_DELAY (1ull << 62)

/* Feed the oldest sentmeta-lost pn into the resend slot only when the loop
 * captured none of its own (RFC 9002 13.3). */
static int take_lost(const quic_connrunner *r, usz n)
{
    return n > 0 && !r->rtx_held;
}

void quic_connrunner_track_loss(quic_connrunner *r, u64 now)
{
    u64 lost[QUIC_SENTMETA_CAP];
    usz n = 0;
    if (!r->io.disp.has_ack) return; /* largest_acked is only valid after an ACK */
    quic_sentmeta_detect_loss(&r->sent, r->io.disp.largest_acked, now,
                              QUIC_CONNRUNNER_NO_RTT_DELAY, lost, &n);
    if (take_lost(r, n)) r->rtx_pn = lost[0], r->rtx_held = 1;
}
