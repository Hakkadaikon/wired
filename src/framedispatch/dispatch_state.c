#include "framedispatch/dispatch_state.h"
#include "frame/dispatch.h"
#include "frame/frame.h"
#include "frame/ack.h"
#include "frame/flowctl.h"
#include "sentpkt/ack_process.h"

/* RFC 9000 19.8: feed a STREAM frame's bytes into the read buffer. */
static int on_stream(quic_framedispatch_state *st, const u8 *frame, usz len)
{
    quic_stream_frame f;
    if (quic_frame_get_stream(frame, len, &f) == 0) return 0;
    return quic_stream_read_push(st->stream, f.offset, f.data, f.length);
}

/* RFC 9000 19.3: an ACK frame is decoded to its ranges, then replayed as the
 * wire (first_len, gap, range_len, ...) form the sent table consumes. */
static int on_ack(quic_framedispatch_state *st, const u8 *frame, usz len)
{
    quic_ack_frame f;
    if (quic_ack_decode(frame, len, &f) == 0) return 0;
    st->has_ack = 1; /* RFC 9000 19.3: expose Largest Acknowledged to the runner */
    st->largest_acked = f.ranges[0].hi;
    u64 wire[2 * QUIC_ACK_MAX_RANGES];
    usz w = 0;
    wire[w++] = f.ranges[0].hi - f.ranges[0].lo;
    for (usz i = 1; i < f.n_ranges; i++) {
        wire[w++] = f.ranges[i - 1].lo - f.ranges[i].hi - 2;
        wire[w++] = f.ranges[i].hi - f.ranges[i].lo;
    }
    u64 acked[QUIC_SENTPKT_CAP];
    usz n = 0;
    quic_ack_process(st->sent, f.ranges[0].hi, wire, w, acked, &n);
    return 1;
}

/* RFC 9000 19.9: MAX_DATA raises the peer's send limit; mirror it as our
 * credit's advertised max so a later overrun is detectable. */
static int on_max_data(quic_framedispatch_state *st, const u8 *frame, usz len)
{
    quic_data_frame f;
    if (quic_max_data_decode(frame, len, &f) == 0) return 0;
    st->credit->max_data = f.value;
    return 1;
}

/* RFC 9000 19.19: record that the peer is closing. */
static int on_close(quic_framedispatch_state *st, const u8 *frame, usz len)
{
    (void)frame; (void)len;
    st->close = 1;
    return 1;
}

/* PADDING (19.1) and PING (19.2) carry no state beyond the ack-eliciting
 * flag handled by the caller. */
static int on_noop(quic_framedispatch_state *st, const u8 *frame, usz len)
{
    (void)st; (void)frame; (void)len;
    return 1;
}

typedef int (*handler)(quic_framedispatch_state *, const u8 *, usz);

/* RFC 9000 12.4: one handler per frame kind, indexed by quic_frame_kind. */
static const handler handlers[] = {
    [QUIC_FK_PADDING]          = on_noop,
    [QUIC_FK_PING]             = on_noop,
    [QUIC_FK_ACK]              = on_ack,
    [QUIC_FK_STREAM]           = on_stream,
    [QUIC_FK_MAX_DATA]         = on_max_data,
    [QUIC_FK_CONNECTION_CLOSE] = on_close,
};

int quic_framedispatch_ack_eliciting(u64 frame_type)
{
    return quic_frame_ack_eliciting(quic_frame_classify(frame_type));
}

int quic_framedispatch_handle(quic_framedispatch_state *st, u64 frame_type,
                              const u8 *frame, usz len)
{
    quic_frame_kind k = quic_frame_classify(frame_type);
    handler h = (k < sizeof handlers / sizeof handlers[0]) ? handlers[k] : 0;
    if (h == 0) return 0;
    st->ack_eliciting |= (u8)quic_frame_ack_eliciting(k);
    return h(st, frame, len);
}
