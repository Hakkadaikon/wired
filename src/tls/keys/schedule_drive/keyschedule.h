#ifndef QUIC_SCHEDULE_DRIVE_KEYSCHEDULE_H
#define QUIC_SCHEDULE_DRIVE_KEYSCHEDULE_H

#include "tls/handshake/core/tls/initial.h"

/* RFC 8446 7.1: order-driven key schedule. Drives the existing secret/key
 * derivations in lock-step with handshake progress: Early -> Handshake
 * (mix in ECDHE) -> Master, each stage producing traffic keys. Out-of-order
 * advances are rejected. */

/* which: handshake/application packet-protection keys per direction. */
enum {
    QUIC_KS_CLIENT_HS = 0,
    QUIC_KS_SERVER_HS = 1,
    QUIC_KS_CLIENT_AP = 2,
    QUIC_KS_SERVER_AP = 3,
};

typedef struct {
    int stage; /* 0=init/early, 1=handshake, 2=master */
    u8 master[QUIC_HKDF_PRK];
    quic_initial_keys keys[4];
} quic_keysched;

/* Enter the Early Secret stage. */
void quic_keysched_init(quic_keysched *st);

/* ServerHello received: derive Handshake Secret from the ECDHE shared secret
 * and the client/server handshake traffic keys over the transcript. Returns 1
 * on success, 0 if the stage is not init (order violation). */
int quic_keysched_advance_handshake(quic_keysched *st,
                                    const u8 *ecdhe, usz ecdhe_len,
                                    const u8 *transcript, usz transcript_len);

/* Finished processed: derive Master Secret and the application traffic keys.
 * Returns 1 on success, 0 if the stage is not handshake (order violation). */
int quic_keysched_advance_master(quic_keysched *st,
                                 const u8 *transcript, usz transcript_len);

/* If the keys for `which` have been derived, point *out at them and return 1;
 * otherwise return 0. */
int quic_keysched_get(const quic_keysched *st, int which,
                      const quic_initial_keys **out);

#endif
