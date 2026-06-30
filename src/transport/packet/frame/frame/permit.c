#include "transport/packet/frame/frame/permit.h"

/* Bit per packet type (Initial=1, Handshake=2, 0-RTT=4, 1-RTT=8). */
#define I 0x1
#define H 0x2
#define Z 0x4
#define O 0x8
#define ALL (I | H | Z | O)

/* Allowed packet types per frame kind, indexed by quic_frame_kind. Per RFC
 * 9000 12.4 Table 3: PADDING/PING are IH01; ACK and CRYPTO are IH_1 (not
 * 0-RTT); CONNECTION_CLOSE(transport) is IH01; the rest are application
 * data, 0-RTT and 1-RTT only. */
static const u8 allowed[] = {
    [QUIC_FK_UNKNOWN]              = 0,
    [QUIC_FK_PADDING]             = ALL,
    [QUIC_FK_PING]                = ALL,
    [QUIC_FK_ACK]                 = I | H | O,
    [QUIC_FK_RESET_STREAM]        = Z | O,
    [QUIC_FK_STOP_SENDING]        = Z | O,
    [QUIC_FK_CRYPTO]              = I | H | O,
    [QUIC_FK_NEW_TOKEN]           = O,
    [QUIC_FK_STREAM]              = Z | O,
    [QUIC_FK_MAX_DATA]            = Z | O,
    [QUIC_FK_MAX_STREAM_DATA]     = Z | O,
    [QUIC_FK_MAX_STREAMS]         = Z | O,
    [QUIC_FK_DATA_BLOCKED]        = Z | O,
    [QUIC_FK_STREAM_DATA_BLOCKED] = Z | O,
    [QUIC_FK_STREAMS_BLOCKED]     = Z | O,
    [QUIC_FK_NEW_CONNECTION_ID]   = Z | O,
    [QUIC_FK_RETIRE_CONNECTION_ID] = Z | O,
    [QUIC_FK_PATH_CHALLENGE]      = Z | O,
    [QUIC_FK_PATH_RESPONSE]       = O,
    [QUIC_FK_CONNECTION_CLOSE]    = I | H | Z | O,
    [QUIC_FK_HANDSHAKE_DONE]      = O,
    [QUIC_FK_DATAGRAM]            = Z | O,
};

int quic_frame_permitted(quic_frame_kind kind, quic_packet_type pkt)
{
    return (allowed[kind] >> pkt) & 1;
}

int quic_frame_is_grease(u64 type)
{
    if (type < 0x21) return 0;
    return (type - 0x21) % 0x1f == 0; /* 0x1f*N + 0x21 reserved points */
}
