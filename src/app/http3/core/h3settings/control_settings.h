#ifndef H3SETTINGS_CONTROL_SETTINGS_H
#define H3SETTINGS_CONTROL_SETTINGS_H

#include "app/http3/core/h3settings/settings_build.h"
#include "app/qpack/qpack/dyntable.h"
#include "common/platform/sys/syscall.h"
#include "common/profile/moqt_room.h"

/** RFC 9114 4.2.2 / 7.2.4.1: the field-section limit this server advertises
 * (SETTINGS_MAX_FIELD_SECTION_SIZE) and, equally, the capacity of the
 * per-stream decode scratch that must hold a compliant section -- the
 * accounted section size adds 32 per field on top of the name+value bytes,
 * so a buffer of exactly this many bytes always fits a section the peer
 * kept within the limit. One constant so the wire promise and the buffer
 * can never diverge: Chrome's ~0.9 KiB of decoded request headers
 * overflowed the old separate 512-byte scratch while the SETTINGS
 * advertised 16 KiB, and every request was aborted as incomplete. */
/* Sizing: RFC 9110 4.1 recommends accepting URIs of at least 8000 octets;
 * an 8000-octet :path line accounts 8000 + 5 + 32, leaving ~2 KiB for the
 * other pseudo-headers and a browser's regular fields. */
#define WIRED_H3_MAX_FIELD_SECTION 10240

/** RFC 9204 5 (SETTINGS_QPACK_MAX_TABLE_CAPACITY): the dynamic table
 * capacity this server advertises to peers, bounding the peer's encoder:
 * exactly what the table's byte ring holds, so any entry the capacity
 * admits can be stored (RFC 9204 3.2.2). */
#define DEFAULT_QPACK_MAX_TABLE_CAP QPACK_DYN_MAX_CAPACITY

/** draft-ietf-webtrans-http3-16 5.5.2: the value of
 * SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI -- the client bidi streams one
 * session may open before a
 * WT_MAX_STREAMS raise (srvrun sends one per stream that ends, 5.6). The
 * whole WT bidi reassembly table (WIRED_SRVLOOP_MAX_WT_STREAMS, 24): a MoQT
 * client keeps its request streams open for the session's life.
 * The moqt_chat room profile (WIRED_PROFILE_MOQT_ROOM,
 * common/profile/moqt_room.h) raises it. */
#ifndef H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE
#define H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE 24
#endif

/** draft-ietf-webtrans-http3-16 5.5.1: the value of
 * SETTINGS_WT_INITIAL_MAX_STREAMS_UNI. The WT uni reassembly table
 * (WIRED_SRVLOOP_MAX_WT_UNI_STREAMS, 9) less the three uni streams an HTTP/3
 * client holds for control and QPACK.
 * The moqt_chat room profile (WIRED_PROFILE_MOQT_ROOM,
 * common/profile/moqt_room.h) raises it. */
#ifndef H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE
#define H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE 6
#endif

/** draft-ietf-webtrans-http3-16 5.5.3: the SETTINGS_WT_INITIAL_MAX_DATA
 * value, one receive window (WIRED_SRVLOOP_WT_BUF_CAP, 49152) for each
 * stream the two limits above let a session hold open: (24 + 6) * 49152 =
 * 1474560 by default (srvrun_impl_wtx.h checks the window size). srvrun
 * raises it to the bytes consumed plus this much as the app takes data.
 *
 * All three are non-zero, so flow control is enabled (5.1: this server
 * pools up to SRVRUN_MAX_WT_SESSIONS sessions on one connection, which MUST
 * enable it); srvrun raises WT_MAX_STREAMS / WT_MAX_DATA by capsule on the
 * CONNECT stream's send slot, which retransmits lost bytes (RFC 9000
 * 13.3). */
#define H3SETTINGS_WT_INIT_DATA_VALUE       \
  ((H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE + \
    H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE) * \
   49152ULL)

/** Bytes one server control stream's type + SETTINGS frame can take
 * (h3settings_control_stream); every caller sizes its buffer with this.
 * Worst case 82: type 1 + frame type 1 + length 2 + pairs 78 -- the three
 * WT flow-control limits are 8-byte varints (10 each with their ids), the
 * 0xc671706a max-sessions id alone is 8, and a grease pair is up to 16. */
#define H3SETTINGS_CONTROL_STREAM_MAX 96

/* RFC 9114 6.2.1 / 7.2.4: the opening bytes of an HTTP/3 control stream:
 * stream type 0x00 followed by a SETTINGS frame with default values. When
 * advertise_wt is non-zero the SETTINGS additionally carry SETTINGS_H3_
 * DATAGRAM=1 (RFC 9297 2.1.1) and SETTINGS_WEBTRANSPORT_MAX_SESSIONS=1
 * (draft-ietf-webtrans-http3 8.2) -- the pair a browser requires before it
 * will open a WebTransport session; only advertise it when the QUIC
 * transport also negotiated max_datagram_frame_size (RFC 9297 2.1.1 makes
 * that a MUST). Returns 1 ok with *out_len set, 0 if no room. */
int h3settings_control_stream(int advertise_wt, u8* out, usz cap, usz* out_len);

/* RFC 9114 7.2.4.2 (9114-066): "If the server cannot determine that the
 * settings remembered by a client are compatible with its current
 * settings, it MUST NOT accept 0-RTT data. Remembered settings are
 * compatible if a client complying with those settings would not violate
 * the server's current settings." Every settings value this SDK sends
 * (settings_build.h's h3settings_in, minus grease_id -- a
 * per-connection random reserved identifier the client is required to
 * ignore regardless of value, RFC 9114 7.2.8) is a limit that only gets
 * MORE permissive as it grows (a higher table capacity, more blocked
 * streams, a larger field section, or datagram/CONNECT-protocol/WebTransport
 * support switched on rather than off); a client complying with `prior`
 * cannot be violated by `current` as long as every one of those fields in
 * `current` is at least as permissive as in `prior`.
 * @param prior   the settings sent on the connection that issued the
 *   resumed ticket (what the client remembers and complies with)
 * @param current the settings this connection is about to send while
 *   accepting 0-RTT
 * @return 1 if compatible (safe to accept 0-RTT), 0 if not (the caller
 *   MUST NOT accept 0-RTT data) */
int h3settings_zerortt_compatible(
    const h3settings_in* prior, const h3settings_in* current);

/* RFC 9114 7.2.4.2 (9114-066): the SETTINGS this server sends are a pure
 * function of whether it advertised max_datagram_frame_size
 * (h3settings_control_stream's advertise_wt), a value the session ticket
 * remembers (ticket.tp[STP_REMEMBERED_DGRAM]) -- so the settings the client
 * remembers are rebuilt from the ticket's value and checked against the
 * ones this connection will send (h3settings_zerortt_compatible).
 * @param prior_max_datagram the ticket's remembered max_datagram_frame_size
 * @param current_max_datagram the one this connection advertises
 * @return 1 if 0-RTT may be accepted under the remembered SETTINGS, 0 if
 *   not */
int h3settings_zerortt_remembered_ok(
    u64 prior_max_datagram, u64 current_max_datagram);

#endif
