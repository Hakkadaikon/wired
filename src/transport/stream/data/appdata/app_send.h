#ifndef QUIC_APPDATA_APP_SEND_H
#define QUIC_APPDATA_APP_SEND_H

#include "transport/packet/protect/protect/protect.h"

/* One outgoing 1-RTT STREAM payload: the short-header DCID, the packet
 * number, and the stream data to frame. */
typedef struct {
  quic_span dcid;
  u64       pn;
  u64       stream_id;
  quic_span data;
  int       fin;
} quic_appdata_tx;

/* RFC 9001 5: carry application data in a 1-RTT (short header) packet. The
 * data is framed as a STREAM frame (RFC 9000 19.8) and sealed with the 1-RTT
 * keys into out; length to out->len. Returns 1, or 0 on overflow. */
int quic_appdata_send(
    const quic_protect_keys* k, const quic_appdata_tx* tx, quic_obuf* out);

#endif
