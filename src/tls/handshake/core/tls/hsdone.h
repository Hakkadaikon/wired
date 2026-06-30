#ifndef QUIC_TLS_HSDONE_H
#define QUIC_TLS_HSDONE_H

/* RFC 9001 4.1.1: handshake completion and confirmation. The TLS handshake
 * is complete when the peer's Finished is verified and the local Finished is
 * sent. It is confirmed on the server when HANDSHAKE_DONE is sent, on the
 * client when HANDSHAKE_DONE is received. */

int quic_hs_complete(int finished_verified, int finished_sent);

int quic_hs_confirmed(int is_server, int handshake_done_sent,
                      int handshake_done_received);

#endif
