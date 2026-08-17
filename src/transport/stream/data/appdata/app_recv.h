#ifndef APPDATA_APP_RECV_H
#define APPDATA_APP_RECV_H

#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/protect/protect/protect.h"

/** One received 1-RTT packet: the bytes (opened in place) and the connection's
 * short-header DCID length. */
typedef struct {
  wired_mspan pkt;
  u8          dcid_len;
} appdata_pkt;

/* RFC 9001 5: open a 1-RTT packet with the 1-RTT keys and decode the STREAM
 * frame (RFC 9000 19.8) it carries into *f (f->data points into the packet).
 * Returns 1, or 0 on authentication failure, short input, or malformed
 * frame. */
int appdata_recv(const protect_keys* k, const appdata_pkt* p, stream_frame* f);

#endif
