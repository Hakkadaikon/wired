#ifndef QUIC_VPN_VPN_OPEN_H
#define QUIC_VPN_VPN_OPEN_H

#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.4.1: remove header protection on a long-header Initial whose
 * packet-number length is unknown until byte0 is unmasked, then AEAD-open.
 *   pkt/len : the received packet buffer (modified in place).
 *   pn_off  : offset of the (still protected) packet number field.
 *   length  : the Length field value = packet number + payload + tag bytes,
 *             so the protected region runs [pn_off, pn_off+length).
 * On success returns 1 with payload pointing at the decrypted frames inside
 * pkt and payload_len their length; on authentication failure returns 0. */
int quic_vpn_open(const quic_initial_keys *keys, const quic_aes128 *hp, u8 *pkt,
                  usz len, usz pn_off, u64 length, const u8 **payload,
                  usz *payload_len);

#endif
