#ifndef XDPFRAME_IMPL_H
#define XDPFRAME_IMPL_H

#include "transport/io/xdp/xdpframe/xdpframe.h"

/* Internal to xdpframe: the IPv6 half (xdpframe_v6.c) and the helper both
 * halves share. */

/* Write the eth header for m with ethertype at the frame start p. */
void xdpframe_put_eth(u8* p, const xdpframe_tx* m, u16 ethertype);

/* RFC 8200: validate and decode the IPv6 + UDP part starting at ip (rem
 * bytes to the frame end) into out. 1 accepted, 0 rejected. */
int xdpframe_parse6(const u8* ip, usz rem, u32 flags, xdpframe_rx* out);

/* eth + IPv6 + UDP around payload, or 0 if frame.n is too small. */
usz xdpframe_build6(
    wired_mspan frame, const xdpframe_tx* m, wired_span payload);

#endif
