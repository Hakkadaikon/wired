#ifndef APPDATA_APP_RECV_H
#define APPDATA_APP_RECV_H

#include "transport/packet/protect/protect/protect.h"

/** One received 1-RTT packet: the bytes (opened in place) and the connection's
 * short-header DCID length. */
typedef struct {
  wired_mspan pkt;
  u8          dcid_len;
} appdata_pkt;

#endif
