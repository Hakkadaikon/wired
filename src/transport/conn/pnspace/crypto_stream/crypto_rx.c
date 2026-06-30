#include "transport/conn/pnspace/crypto_stream/crypto_rx.h"

void quic_crypto_stream_rx_init(quic_crypto_rx *r)
{
    quic_reasm_init(&r->reasm);
    r->read_upto = 0;
}

/* RFC 9000 19.6 */
int quic_crypto_stream_recv(quic_crypto_rx *r, u64 offset,
                            const u8 *data, usz len)
{
    return quic_reasm_insert(&r->reasm, offset, data, len);
}

/* RFC 9000 7.5 */
int quic_crypto_stream_read(quic_crypto_rx *r, u8 *out, usz cap, usz *out_len)
{
    u64 avail = quic_reasm_deliver(&r->reasm) - r->read_upto;
    if (avail > cap) return 0;
    for (u64 i = 0; i < avail; i++) out[i] = r->reasm.buf[r->read_upto + i];
    r->read_upto += avail;
    *out_len = (usz)avail;
    return 1;
}
