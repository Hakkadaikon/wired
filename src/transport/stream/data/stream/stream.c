#include "transport/stream/data/stream/stream.h"
#include "transport/conn/lifecycle/fsm/fsm.h"

/* Transition tables: a step is allowed iff (from, event) names a row, and
 * it moves the state to that row's `to`. Table-driven keeps CCN minimal and
 * makes the legal RFC 9000 3.1/3.2 transitions auditable in one place. */

typedef quic_fsm_row row;

/* RFC 9000 3.1 sending part. RESET is legal from any pre-terminal state. */
static const row send_rows[] = {
    {QUIC_SEND_READY,     QUIC_SEND_EV_STREAM,     QUIC_SEND_SEND},
    {QUIC_SEND_SEND,      QUIC_SEND_EV_FIN_SENT,   QUIC_SEND_DATA_SENT},
    {QUIC_SEND_DATA_SENT, QUIC_SEND_EV_ACKED,      QUIC_SEND_DATA_RECVD},
    {QUIC_SEND_READY,     QUIC_SEND_EV_RESET,      QUIC_SEND_RESET_SENT},
    {QUIC_SEND_SEND,      QUIC_SEND_EV_RESET,      QUIC_SEND_RESET_SENT},
    {QUIC_SEND_DATA_SENT, QUIC_SEND_EV_RESET,      QUIC_SEND_RESET_SENT},
    {QUIC_SEND_RESET_SENT, QUIC_SEND_EV_RESET_ACKED, QUIC_SEND_RESET_RECVD},
};

/* RFC 9000 3.2 receiving part. RESET is legal before all data is received. */
static const row recv_rows[] = {
    {QUIC_RECV_RECV,        QUIC_RECV_EV_FIN,      QUIC_RECV_SIZE_KNOWN},
    {QUIC_RECV_SIZE_KNOWN,  QUIC_RECV_EV_ALL_DATA, QUIC_RECV_DATA_RECVD},
    {QUIC_RECV_DATA_RECVD,  QUIC_RECV_EV_READ,     QUIC_RECV_DATA_READ},
    {QUIC_RECV_RECV,        QUIC_RECV_EV_RESET,    QUIC_RECV_RESET_RECVD},
    {QUIC_RECV_SIZE_KNOWN,  QUIC_RECV_EV_RESET,    QUIC_RECV_RESET_RECVD},
    {QUIC_RECV_RESET_RECVD, QUIC_RECV_EV_READ,     QUIC_RECV_RESET_READ},
};

int quic_send_step(quic_send_state *s, quic_send_event ev)
{
    u8 st = (u8)*s;
    int ok = quic_fsm_step(&st, send_rows, sizeof(send_rows) / sizeof(row), (u8)ev);
    *s = (quic_send_state)st;
    return ok;
}

int quic_recv_step(quic_recv_state *s, quic_recv_event ev)
{
    u8 st = (u8)*s;
    int ok = quic_fsm_step(&st, recv_rows, sizeof(recv_rows) / sizeof(row), (u8)ev);
    *s = (quic_recv_state)st;
    return ok;
}
