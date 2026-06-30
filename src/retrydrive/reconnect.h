#ifndef QUIC_RETRYDRIVE_RECONNECT_H
#define QUIC_RETRYDRIVE_RECONNECT_H

#include "common/platform/sys/syscall.h"
#include "transport/packet/header/packet/header.h"

/* RFC 9000 17.2.5: reconnection state after a client accepts a Retry. Holds
 * the token to put in every subsequent Initial, the new DCID (the Retry's
 * SCID), and key_rederive: the Initial keys must be re-derived because the
 * Initial secret is salted with the DCID (RFC 9001 5.2). */
typedef struct {
    int received;                  /* a Retry has been accepted */
    int key_rederive;              /* Initial keys must be re-derived */
    u8 token[256];                 /* Retry token (server-opaque, RFC 9000 8.1.2) */
    usz token_len;
    u8 dcid[QUIC_MAX_CID_LEN];     /* new DCID = Retry SCID */
    u8 dcid_len;
} quic_retrydrive_state;

/* RFC 9000 17.2.5.2: record the accepted Retry into out: store the token for
 * later Initials, adopt retry_scid as the new DCID, and flag Initial key
 * re-derivation. Returns 0 (and leaves out untouched) if the token or SCID
 * exceeds the buffers; 1 on success. */
int quic_retrydrive_apply(const u8 *retry_token, usz token_len,
                          const u8 *retry_scid, usz scid_len,
                          quic_retrydrive_state *out);

#endif
