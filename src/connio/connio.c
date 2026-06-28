#include "connio/connio.h"
#include "pipeline/txpacket.h"
#include "pipeline/rxpacket.h"
#include "pipeline/framewalk.h"
#include "aes/aes.h"

void quic_connio_init(quic_connio *io, int is_server, u8 byte0,
                      const u8 *dcid, u8 dcid_len, u64 initial_max_data)
{
    usz i;
    quic_connloop_init(&io->loop, is_server);
    quic_stream_read_init(&io->stream);
    quic_flow_credit_init(&io->credit, initial_max_data);
    io->disp.stream = &io->stream;
    io->disp.sent = &io->loop.sent;
    io->disp.credit = &io->credit;
    io->disp.ack_eliciting = 0;
    io->disp.close = 0;
    io->byte0 = byte0;
    io->dcid_len = dcid_len;
    io->tx_pn = 0;
    io->rx_pn = 0;
    for (i = 0; i < dcid_len; i++) io->dcid[i] = dcid[i];
}

/* RFC 9001 4: a level may send only once its keys are installed and the
 * connloop gate (level monotonicity, anti-amp, phase) admits the packet. */
static int send_ready(quic_connio *io, int level, usz len,
                      const quic_initial_keys **keys)
{
    /* ponytail: ack-eliciting hard-set to 1; frames here always elicit (STREAM/
     * PING). Classify frames[0] if a non-eliciting-only send is ever needed. */
    return quic_connloop_on_send(&io->loop, level, 1, io->tx_pn, len)
        && quic_keyset_for_level(&io->loop.keys, level, keys);
}

usz quic_connio_send(quic_connio *io, int level, const u8 *frames,
                     usz frames_len, u8 *out, usz cap)
{
    const quic_initial_keys *keys;
    quic_aes128 hp;
    usz n;
    if (!send_ready(io, level, frames_len, &keys)) return 0;
    quic_aes128_init(&hp, keys->hp);
    n = quic_tx_packet(keys, &hp, io->byte0, io->dcid, io->dcid_len,
                       io->tx_pn, frames, frames_len, out, cap);
    io->tx_pn++;
    return n;
}

/* RFC 9000 12.4: walk the recovered payload and dispatch each frame into the
 * receive state. Returns 1 if every frame was handled. */
static int dispatch_all(quic_connio *io, const u8 *frames, usz frames_len)
{
    quic_framewalk it;
    const u8 *frame;
    u64 type;
    usz rem;
    int ok = 1;
    quic_framewalk_init(&it, frames, frames_len);
    while (quic_framewalk_next(&it, &type, &frame, &rem))
        ok &= quic_framedispatch_handle(&io->disp, type, frame, rem);
    return ok;
}

/* RFC 9001 4: a level may process a datagram only once its keys are installed
 * and the connloop gate (phase, discarded level) admits it. */
static int recv_ready(quic_connio *io, int level, usz len,
                      const quic_initial_keys **keys)
{
    return quic_connloop_on_recv(&io->loop, level, len)
        && quic_keyset_for_level(&io->loop.keys, level, keys);
}

int quic_connio_recv(quic_connio *io, int level, u8 *datagram, usz len)
{
    const quic_initial_keys *keys;
    quic_aes128 hp;
    const u8 *frames;
    usz frames_len;
    if (!recv_ready(io, level, len, &keys)) return 0;
    quic_aes128_init(&hp, keys->hp);
    if (!quic_rx_packet(keys, &hp, datagram, len, io->dcid_len, io->rx_pn,
                        &frames, &frames_len))
        return 0;
    io->rx_pn++;
    return dispatch_all(io, frames, frames_len);
}
