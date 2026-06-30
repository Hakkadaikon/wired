#include "transport/conn/loop/crecv/message.h"

void quic_crecv_message(const quic_crecv *s, const u8 **msg, usz *len)
{
    *msg = s->buf;
    *len = s->received_to;
}

/* RFC 8446 4: handshake message = 1-byte type + 3-byte big-endian body len. */
static usz msg_total(const u8 *b)
{
    return 4 + ((usz)b[1] << 16 | (usz)b[2] << 8 | (usz)b[3]);
}

int quic_crecv_complete_message(const quic_crecv *s)
{
    if (s->received_to < 4) return 0;
    return msg_total(s->buf) <= s->received_to;
}
