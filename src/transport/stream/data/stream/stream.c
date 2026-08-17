#include "transport/stream/data/stream/stream.h"

#include "transport/conn/lifecycle/fsm/fsm.h"

/* Transition tables: a step is allowed iff (from, event) names a row, and
 * it moves the state to that row's `to`. Table-driven keeps CCN minimal and
 * makes the legal RFC 9000 3.1/3.2 transitions auditable in one place. */

typedef fsm_row row;

/* RFC 9000 3.1 sending part. RESET is legal from any pre-terminal state. */
static const row send_rows[] = {
    {SEND_READY, SEND_EV_STREAM, SEND_SEND},
    {SEND_SEND, SEND_EV_FIN_SENT, SEND_DATA_SENT},
    {SEND_DATA_SENT, SEND_EV_ACKED, SEND_DATA_RECVD},
    {SEND_READY, SEND_EV_RESET, SEND_RESET_SENT},
    {SEND_SEND, SEND_EV_RESET, SEND_RESET_SENT},
    {SEND_DATA_SENT, SEND_EV_RESET, SEND_RESET_SENT},
    {SEND_RESET_SENT, SEND_EV_RESET_ACKED, SEND_RESET_RECVD},
};

/* RFC 9000 3.2 receiving part. RESET is legal before all data is received. */
static const row recv_rows[] = {
    {RECV_RECV, RECV_EV_FIN, RECV_SIZE_KNOWN},
    {RECV_SIZE_KNOWN, RECV_EV_ALL_DATA, RECV_DATA_RECVD},
    {RECV_DATA_RECVD, RECV_EV_READ, RECV_DATA_READ},
    {RECV_RECV, RECV_EV_RESET, RECV_RESET_RECVD},
    {RECV_SIZE_KNOWN, RECV_EV_RESET, RECV_RESET_RECVD},
    {RECV_RESET_RECVD, RECV_EV_READ, RECV_RESET_READ},
};

int send_step(send_state* s, send_event ev) {
  u8        st    = (u8)*s;
  fsm_table table = {send_rows, sizeof(send_rows) / sizeof(row)};
  int       ok    = fsm_step(&st, &table, (u8)ev);
  *s              = (send_state)st;
  return ok;
}

int recv_step(recv_state* s, recv_event ev) {
  u8        st    = (u8)*s;
  fsm_table table = {recv_rows, sizeof(recv_rows) / sizeof(row)};
  int       ok    = fsm_step(&st, &table, (u8)ev);
  *s              = (recv_state)st;
  return ok;
}
