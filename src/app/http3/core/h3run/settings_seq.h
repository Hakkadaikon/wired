#ifndef QUIC_H3RUN_SETTINGS_SEQ_H
#define QUIC_H3RUN_SETTINGS_SEQ_H

#include "app/http3/core/h3/frame.h" /* QUIC_H3_FRAME_SETTINGS */
#include "common/platform/sys/syscall.h"

/* RFC 9114 7.2.4: the first frame on a control stream MUST be SETTINGS (0x04),
 * else H3_MISSING_SETTINGS. SETTINGS appears exactly once per control stream.
 */

typedef struct {
  u8 settings_done; /* the (single) SETTINGS frame was accepted */
} quic_h3_settings_state;

/* Validate the first control frame. Returns 1 if it is SETTINGS and SETTINGS
 * has not yet been seen; 0 otherwise (wrong first frame, or a 2nd SETTINGS). */
int quic_h3_settings_first(quic_h3_settings_state *state, u64 first_frame_type);

#endif
