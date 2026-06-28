#include "connrunner/send.h"
#include "frame/ack.h"
#include "frame/frame.h"

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

/* RFC 9000 19.3: an ACK acknowledging up to the highest received packet number.
 * connio.rx_pn is the next expected number, so the largest seen is rx_pn-1. */
static usz cr_build_ack(const quic_connrunner *r, u8 *buf, usz cap)
{
    quic_ack_frame f = {0};
    if (r->io.rx_pn == 0) return 0; /* nothing received to acknowledge */
    f.n_ranges = 1;
    f.ranges[0].hi = r->io.rx_pn - 1;
    f.ranges[0].lo = r->io.rx_pn - 1;
    return quic_ack_encode(buf, cap, &f);
}

/* RFC 9000 19.7: a minimal ack-eliciting payload stands in for retransmitted or
 * new application data at this layer. */
static usz cr_build_ping(u8 *buf, usz cap)
{
    return quic_frame_put_simple(buf, cap, QUIC_FRAME_PING);
}

/* Build the frame bytes for the chosen kind into buf (1=ACK, 2/3=data stand-in,
 * 0=nothing). Returns the length. */
static usz cr_build_frames(const quic_connrunner *r, int kind, u8 *buf, usz cap)
{
    if (kind == 1) return cr_build_ack(r, buf, cap);
    if (kind == 0) return 0;
    return cr_build_ping(buf, cap); /* retransmission or new data */
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
