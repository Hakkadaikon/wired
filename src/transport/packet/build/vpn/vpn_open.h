#ifndef QUIC_VPN_VPN_OPEN_H
#define QUIC_VPN_VPN_OPEN_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5.4.1: remove header protection on a long-header Initial whose
 * packet-number length is unknown until byte0 is unmasked, then AEAD-open. */

/* One received packet to open in place.
 *   pkt    : the received packet buffer (modified in place).
 *   pn_off : offset of the (still protected) packet number field.
 *   length : the Length field value = packet number + payload + tag bytes,
 *            so the protected region runs [pn_off, pn_off+length). */
typedef struct {
  quic_mspan pkt;
  usz        pn_off;
  u64        length;
} quic_vpn_desc;

/* On success returns 1 with *payload viewing the decrypted frames inside
 * pkt; on authentication failure returns 0 (AES-128-GCM; equivalent to
 * quic_vpn_open_suite with suite = QUIC_TLS_AES_128_GCM_SHA256). */
int quic_vpn_open(
    const quic_protect_keys* k, const quic_vpn_desc* d, quic_span* payload);

/* Same as quic_vpn_open, but opens under the given negotiated TLS 1.3 cipher
 * suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_vpn_open_suite(
    u16                      suite,
    const quic_protect_keys* k,
    const quic_vpn_desc*     d,
    quic_span*               payload);

#endif
