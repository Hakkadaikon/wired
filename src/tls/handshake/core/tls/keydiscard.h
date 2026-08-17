#ifndef TLS_KEYDISCARD_H
#define TLS_KEYDISCARD_H

/* RFC 9001 4.9.1: Initial keys are discarded once Handshake keys are
 * available; Handshake keys are discarded once the handshake is confirmed
 * (1-RTT keys in use). */

int key_discard_initial(int handshake_keys_available);

int key_discard_handshake(int handshake_confirmed);

#endif
