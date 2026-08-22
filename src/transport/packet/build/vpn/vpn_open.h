#ifndef VPN_VPN_OPEN_H
#define VPN_VPN_OPEN_H

#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5.4.1: remove header protection on a long-header Initial whose
 * packet-number length is unknown until byte0 is unmasked, then AEAD-open. */

/** One received packet to open in place.
 *   pkt        : the received packet buffer (modified in place).
 *   pn_off     : offset of the (still protected) packet number field.
 *   length     : the Length field value = packet number + payload + tag
 *                bytes, so the protected region runs [pn_off,
 *                pn_off+length).
 *   largest_pn : the largest packet number received so far in this packet's
 *                number space (0 before any). The wire packet number is
 *                truncated (RFC 9000 17.1) and the AEAD nonce needs the
 *                full value, so it is recovered against this baseline
 *                (RFC 9000 A.3) -- a peer whose packets have been acked
 *                truncates harder than the raw wire value can express. */
typedef struct {
  wired_mspan pkt;
  usz         pn_off;
  u64         length;
  u64         largest_pn;
} vpn_desc;

/* On success returns 1 with *payload viewing the decrypted frames inside
 * pkt; on authentication failure returns 0 (AES-128-GCM; equivalent to
 * vpn_open_suite with suite = TLS_AES_128_GCM_SHA256). */
int vpn_open(const protect_keys* k, const vpn_desc* d, wired_span* payload);

/* Same as vpn_open, but opens under the given negotiated TLS 1.3 cipher
 * suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int vpn_open_suite(
    u16 suite, const protect_keys* k, const vpn_desc* d, wired_span* payload);

#endif
