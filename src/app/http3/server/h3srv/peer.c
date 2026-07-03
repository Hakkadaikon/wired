#include "app/http3/server/h3srv/peer.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/stream_type.h"

/* RFC 9114 7.2.4: SETTINGS already recorded and another SETTINGS arrives. */
static int is_second_settings(const wired_h3srv_state *st, u64 ft) {
  return st->peer_settings && ft == QUIC_H3_FRAME_SETTINGS;
}

/* RFC 9114 6.2.1: a control stream is already open and another opens. */
static int is_second_control(const wired_h3srv_state *st, u64 ft) {
  return (st->peer_control >= 1) && ((void)ft, 1);
}

/* RFC 9114 7.2.4: the first frame on the control stream is not SETTINGS. */
static int is_missing_settings(const wired_h3srv_state *st, u64 ft) {
  return (ft != QUIC_H3_FRAME_SETTINGS) && ((void)st, 1);
}

/* Violation classifiers scanned in priority order; first match wins. */
static const struct {
  int (*hit)(const wired_h3srv_state *, u64);
  u16 code;
} peer_control_rules[] = {
    {is_second_settings, QUIC_H3_FRAME_UNEXPECTED},
    {is_second_control, QUIC_H3_STREAM_CREATION_ERROR},
    {is_missing_settings, QUIC_H3_MISSING_SETTINGS},
};

/* Classify the violation, leaving 0 when the frame is an acceptable
 * SETTINGS-first. */
static u16 peer_control_error(const wired_h3srv_state *st, u64 ft) {
  for (usz i = 0; i < sizeof(peer_control_rules) / sizeof(*peer_control_rules);
       i++)
    if (peer_control_rules[i].hit(st, ft)) return peer_control_rules[i].code;
  return 0;
}

/* RFC 9114 6.2.1 / 7.2.4 */
int wired_h3srv_on_peer_control(
    wired_h3srv_state *st, u64 first_frame_type, u16 *err) {
  *err = peer_control_error(st, first_frame_type);
  if (*err) return 0;
  st->peer_control  = 1;
  st->peer_settings = 1;
  return 1;
}

/* RFC 9114 6.2 / RFC 9204 4.2 */
int wired_h3srv_accept_uni(u64 stream_type) {
  return quic_h3_stream_type_is_control(stream_type) ||
         quic_h3_stream_type_is_qpack(stream_type);
}
