#ifndef QUIC_APPDATA_APP_SEND_H
#define QUIC_APPDATA_APP_SEND_H

#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5: carry application data in a 1-RTT (short header) packet. The
 * data is framed as a STREAM frame (RFC 9000 19.8) and sealed with the 1-RTT
 * keys into out (cap bytes); length to *out_len. Returns 1, or 0 on overflow.
 */
int quic_appdata_send(
    const quic_initial_keys *app_keys,
    const quic_aes128       *hp,
    const u8                *dcid,
    u8                       dcid_len,
    u64                      pn,
    u64                      stream_id,
    const u8                *data,
    usz                      len,
    int                      fin,
    u8                      *out,
    usz                      cap,
    usz                     *out_len);

#endif
