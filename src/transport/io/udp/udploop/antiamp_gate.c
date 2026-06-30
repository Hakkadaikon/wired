#include "transport/io/udp/udploop/antiamp_gate.h"
#include "path/antiamp.h"

int quic_udploop_send_allowed(u64 received_bytes, u64 sent_bytes,
                              int address_validated, usz next_len)
{
    if (address_validated) return 1; /* RFC 9000 8.1: no limit once validated */
    return quic_antiamp_can_send(received_bytes, sent_bytes, (u64)next_len);
}
