#ifndef PIPELINE_RXPACKET_H
#define PIPELINE_RXPACKET_H

#include "transport/packet/protect/protect/protect.h"

/** RFC 9001 5: unprotect one inbound long-header packet built by
 * tx_packet. Parses the complete RFC 9000 17.2 header to locate the packet
 * number and Length, removes header protection (recovering the packet-number
 * length), and AEAD-opens the payload in place. is_initial selects whether a
 * Token field is present. */
typedef struct {
  wired_mspan pkt;
  int         is_initial;
  u64         largest_pn; /**< largest packet number received so far in this
                           * packet's number space (0 before any) -- the RFC
                           * 9000 A.3 baseline recovering the truncated wire
                           * packet number for the AEAD nonce */
} rx_desc;

/* On success *frames views the plaintext frame bytes within pkt. Returns 1 on
 * success, 0 if authentication fails or the packet is malformed. */
int rx_packet(const protect_keys* k, const rx_desc* d, wired_span* frames);

#endif
