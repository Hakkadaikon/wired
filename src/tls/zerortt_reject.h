#ifndef QUIC_TLS_ZERORTT_REJECT_H
#define QUIC_TLS_ZERORTT_REJECT_H

/* RFC 9001 4.6.1: if the server rejects 0-RTT, the client must discard the
 * 0-RTT keys and treat the 0-RTT data as needing retransmission in 1-RTT. */
void quic_zerortt_on_reject(int *retransmit_needed, int *discard_keys);

/* server_accepted is 1 if the server accepted 0-RTT, 0 if it rejected. */
int quic_zerortt_accepted(int server_accepted);

#endif
