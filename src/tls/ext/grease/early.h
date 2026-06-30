#ifndef QUIC_GREASE_EARLY_H
#define QUIC_GREASE_EARLY_H

/* RFC 9287 3.1: conditions for greasing the QUIC Bit before the handshake
 * completes. */

/* A client may grease the QUIC Bit early only if it remembers (from a prior
 * connection's NEW_TOKEN or session resumption) that the server advertised
 * grease_quic_bit. */
int quic_greasebit_client_early_ok(int remembered_advertised);

/* A server may grease the QUIC Bit only after it has processed the client's
 * transport parameters and itself advertised grease_quic_bit. */
int quic_greasebit_server_ok(int client_tp_processed, int we_advertised);

#endif
