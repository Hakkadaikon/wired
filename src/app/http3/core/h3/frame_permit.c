#include "app/http3/core/h3/frame_permit.h"

#include "app/http3/core/h3/frame.h"

/* Stream-kind bits packed into a per-frame mask (control=1, request=2, push=4).
 */
#define C (1 << QUIC_H3_STREAM_KIND_CONTROL)
#define R (1 << QUIC_H3_STREAM_KIND_REQUEST)
#define P (1 << QUIC_H3_STREAM_KIND_PUSH)

/* RFC 9114 7.2: streams on which each defined frame type 0x00..0x0d is
 * permitted, indexed by type. Gaps (0x02, 0x06, 0x08..0x0c) and any type
 * outside the table are unknown/grease and permitted everywhere (7.2.8). */
static const int permit_tab[] = {
    [QUIC_H3_FRAME_DATA]         = R | P, /* 7.2.1 */
    [QUIC_H3_FRAME_HEADERS]      = R | P, /* 7.2.2 */
    [QUIC_H3_FRAME_CANCEL_PUSH]  = C,     /* 7.2.3 */
    [QUIC_H3_FRAME_SETTINGS]     = C,     /* 7.2.4 */
    [QUIC_H3_FRAME_PUSH_PROMISE] = R,     /* 7.2.5 */
    [QUIC_H3_FRAME_GOAWAY]       = C,     /* 7.2.6 */
    [QUIC_H3_FRAME_MAX_PUSH_ID]  = C      /* 7.2.7 */
};

#define PERMIT_TAB_N (sizeof permit_tab / sizeof permit_tab[0])

static int permit_mask(u64 frame_type) {
  int m;
  if (frame_type >= PERMIT_TAB_N) return C | R | P; /* 7.2.8 unknown/grease */
  m = permit_tab[frame_type];
  return m ? m : C | R | P; /* gap in table */
}

int quic_h3_frame_on_stream(u64 frame_type, int stream_kind) {
  return (permit_mask(frame_type) >> stream_kind) & 1;
}
