#ifndef QUIC_H3SETTINGS_CONTROL_SETTINGS_H
#define QUIC_H3SETTINGS_CONTROL_SETTINGS_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1 / 7.2.4: the opening bytes of an HTTP/3 control stream:
 * stream type 0x00 followed by a SETTINGS frame with default values. When
 * advertise_wt is non-zero the SETTINGS additionally carry SETTINGS_H3_
 * DATAGRAM=1 (RFC 9297 2.1.1) and SETTINGS_WEBTRANSPORT_MAX_SESSIONS=1
 * (draft-ietf-webtrans-http3 8.2) -- the pair a browser requires before it
 * will open a WebTransport session; only advertise it when the QUIC
 * transport also negotiated max_datagram_frame_size (RFC 9297 2.1.1 makes
 * that a MUST). Returns 1 ok with *out_len set, 0 if no room. */
int quic_h3settings_control_stream(
    int advertise_wt, u8* out, usz cap, usz* out_len);

#endif
