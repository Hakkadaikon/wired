#ifndef QUIC_EARLYDRIVE_EARLYDATA_H
#define QUIC_EARLYDRIVE_EARLYDATA_H

/* RFC 9001 4.5 / RFC 9000 9: drives the interaction between 0-RTT (early
 * data) and connection migration. The 0-RTT keys, the resumption ticket, the
 * UDP send target, and path validation themselves live elsewhere
 * (tlsext/earlydata, tls resumption, udpsess, migrate); this layer only
 * decides whether each step is permitted. */

/* RFC 9001 4.5: a client may send 0-RTT data once it holds 0-RTT keys and a
 * resumption is being offered, before the handshake completes. */
int quic_earlydata_can_send(int has_0rtt_keys, int resumption_offered);

/* RFC 9001 4.5 / RFC 8446 2.3: when the server does not accept 0-RTT, any
 * data sent in 0-RTT must be retransmitted in 1-RTT once the handshake
 * completes. Returns 1 when resending is required. */
int quic_earlydata_must_resend(int server_accepted_0rtt);

/* RFC 9000 9.1: a client migrates only after the new path is validated and
 * (9.0) the handshake is confirmed; migration is not attempted during the
 * handshake. */
int quic_earlydata_can_migrate(int new_path_validated, int handshake_confirmed);

#endif
