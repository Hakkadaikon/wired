#include "transport/packet/frame/frame/dispatch.h"

/* Map each defined frame type value to its kind. STREAM (0x08-0x0f) and the
 * paired types (MAX_STREAMS, *_BLOCKED, CONNECTION_CLOSE, DATAGRAM) list each
 * value explicitly so the lookup stays a single flat table. */
typedef struct {
  u64 type;
  u8  kind;
} kind_row;

static const kind_row TABLE[] = {
    {0x00, FK_PADDING},
    {0x01, FK_PING},
    {0x02, FK_ACK},
    {0x03, FK_ACK},
    {0x04, FK_RESET_STREAM},
    {0x05, FK_STOP_SENDING},
    {0x06, FK_CRYPTO},
    {0x07, FK_NEW_TOKEN},
    {0x08, FK_STREAM},
    {0x09, FK_STREAM},
    {0x0a, FK_STREAM},
    {0x0b, FK_STREAM},
    {0x0c, FK_STREAM},
    {0x0d, FK_STREAM},
    {0x0e, FK_STREAM},
    {0x0f, FK_STREAM},
    {0x10, FK_MAX_DATA},
    {0x11, FK_MAX_STREAM_DATA},
    {0x12, FK_MAX_STREAMS},
    {0x13, FK_MAX_STREAMS},
    {0x14, FK_DATA_BLOCKED},
    {0x15, FK_STREAM_DATA_BLOCKED},
    {0x16, FK_STREAMS_BLOCKED},
    {0x17, FK_STREAMS_BLOCKED},
    {0x18, FK_NEW_CONNECTION_ID},
    {0x19, FK_RETIRE_CONNECTION_ID},
    {0x1a, FK_PATH_CHALLENGE},
    {0x1b, FK_PATH_RESPONSE},
    {0x1c, FK_CONNECTION_CLOSE},
    {0x1d, FK_CONNECTION_CLOSE},
    {0x1e, FK_HANDSHAKE_DONE},
    {0x30, FK_DATAGRAM},
    {0x31, FK_DATAGRAM},
    {0x24, FK_RESET_STREAM_AT}};

frame_kind frame_classify(u64 type) {
  usz n = sizeof(TABLE) / sizeof(TABLE[0]);
  for (usz i = 0; i < n; i++)
    if (TABLE[i].type == type) return (frame_kind)TABLE[i].kind;
  return FK_UNKNOWN;
}

/* Only ACK, PADDING, and CONNECTION_CLOSE are non-ack-eliciting. */
static int non_eliciting(frame_kind k) {
  return k == FK_PADDING || k == FK_ACK || k == FK_CONNECTION_CLOSE;
}

int frame_ack_eliciting(frame_kind kind) {
  if (kind == FK_UNKNOWN) return 0;
  return !non_eliciting(kind);
}
