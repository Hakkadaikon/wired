#ifndef H3SETTINGS_CONTROL_SETTINGS_H
#define H3SETTINGS_CONTROL_SETTINGS_H

#include "app/http3/core/h3settings/settings_build.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1 / 7.2.4: the opening bytes of an HTTP/3 control stream:
 * stream type 0x00 followed by a SETTINGS frame with default values. When
 * advertise_wt is non-zero the SETTINGS additionally carry SETTINGS_H3_
 * DATAGRAM=1 (RFC 9297 2.1.1) and SETTINGS_WEBTRANSPORT_MAX_SESSIONS=1
 * (draft-ietf-webtrans-http3 8.2) -- the pair a browser requires before it
 * will open a WebTransport session; only advertise it when the QUIC
 * transport also negotiated max_datagram_frame_size (RFC 9297 2.1.1 makes
 * that a MUST). Returns 1 ok with *out_len set, 0 if no room. */
int h3settings_control_stream(int advertise_wt, u8* out, usz cap, usz* out_len);

/* RFC 9297 2.1.1 / 9297-014: "When servers decide to accept 0-RTT data, they
 * MUST send a SETTINGS_H3_DATAGRAM setting greater than or equal to the
 * value they sent to the client in the connection where they sent them the
 * NewSessionTicket message." A pure predicate: the caller supplies both the
 * value remembered from the ticket-issuing connection (prior_value) and the
 * value this 0-RTT-accepting connection is about to send (new_value) --
 * mirrors zerortt_policy.h's zerortt_replay_ok, which likewise leaves
 * resolving/storing its own inputs to the caller rather than owning state
 * itself.
 * @param prior_value the SETTINGS_H3_DATAGRAM value sent when the resumed
 *   ticket was issued
 * @param new_value   the value this connection is about to send
 * @return 1 if new_value >= prior_value (ok to send), 0 if it would regress
 *   (H3_SETTINGS_ERROR territory on the client's own validation side) */
int h3settings_h3_datagram_monotonic_ok(u64 prior_value, u64 new_value);

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

#endif
