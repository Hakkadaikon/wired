#ifndef QUIC_APPDATA_APP_RECV_H
#define QUIC_APPDATA_APP_RECV_H

#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5: open a 1-RTT packet with the 1-RTT keys and decode the STREAM
 * frame (RFC 9000 19.8) it carries. On success *data points into pkt and the
 * stream id, offset, length, and fin flag are filled. Returns 1, or 0 on
 * authentication failure, short input, or malformed frame. */
int quic_appdata_recv(
    const quic_initial_keys *app_keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    u8                       dcid_len,
    u64                     *stream_id,
    u64                     *offset,
    const u8               **data,
    usz                     *data_len,
    int                     *fin);

#endif
