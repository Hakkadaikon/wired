#ifndef WIRED_SRVLOOP_H3PEER_H
#define WIRED_SRVLOOP_H3PEER_H

#include "app/http3/core/h3/control.h"
#include "app/http3/core/h3/pushid.h"
#include "common/platform/sys/syscall.h"

/** RFC 9114 6.2 / 7.2 / RFC 9204 4.2: what the peer's control and critical
 * unidirectional streams established on this connection. */
typedef struct {
  /** RFC 9114 7.2.4 / draft-ietf-webtrans-http3-15 SS3.1 (WTH3-009/042): the
   * client control stream's own SETTINGS-ordering / GOAWAY state, latched as
   * each control-stream frame is walked (priority_ctrl.c's
   * ctrl_note_generic) -- ctrl.settings_seen is 1 once the client's SETTINGS
   * has actually arrived, gating WebTransport CONNECT dispatch (srvrun.c)
   * until it has. */
  h3_control ctrl;
  /** RFC 9114 8.1: the first HTTP/3 connection error code they caused
   * (H3_SETTINGS_ERROR, H3_FRAME_ERROR, H3_ID_ERROR,
   * H3_STREAM_CREATION_ERROR, H3_CLOSED_CRITICAL_STREAM), 0 when none;
   * ctrl.error carries the h3_control-latched ones.
   * srvrun closes the connection over either. */
  u16 error;
  /** RFC 9114 7.2.7: the peer's MAX_PUSH_ID, which must never decrease. */
  h3_push_state push;
  /** RFC 9114 6.2 / RFC 9204 4.2: the client uni stream id seen for each
   * critical stream type (index = type: 0 control, 2 QPACK encoder, 3
   * decoder), 0 = none yet (a client uni id is never 0). */
  u64 crit_id[4];
  /** RFC 9297 2.1.1: the client SETTINGS' SETTINGS_H3_DATAGRAM (0 until
   * received or when absent; a value over 1 is an H3_SETTINGS_ERROR). */
  u8 h3_datagram;
} srvloop_h3peer;

#endif
