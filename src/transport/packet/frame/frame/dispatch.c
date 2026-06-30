#include "transport/packet/frame/frame/dispatch.h"

/* Map each defined frame type value to its kind. STREAM (0x08-0x0f) and the
 * paired types (MAX_STREAMS, *_BLOCKED, CONNECTION_CLOSE, DATAGRAM) list each
 * value explicitly so the lookup stays a single flat table. */
typedef struct {
  u64 type;
  u8  kind;
} kind_row;

static const kind_row TABLE[] = {
    {0x00, QUIC_FK_PADDING},
    {0x01, QUIC_FK_PING},
    {0x02, QUIC_FK_ACK},
    {0x03, QUIC_FK_ACK},
    {0x04, QUIC_FK_RESET_STREAM},
    {0x05, QUIC_FK_STOP_SENDING},
    {0x06, QUIC_FK_CRYPTO},
    {0x07, QUIC_FK_NEW_TOKEN},
    {0x08, QUIC_FK_STREAM},
    {0x09, QUIC_FK_STREAM},
    {0x0a, QUIC_FK_STREAM},
    {0x0b, QUIC_FK_STREAM},
    {0x0c, QUIC_FK_STREAM},
    {0x0d, QUIC_FK_STREAM},
    {0x0e, QUIC_FK_STREAM},
    {0x0f, QUIC_FK_STREAM},
    {0x10, QUIC_FK_MAX_DATA},
    {0x11, QUIC_FK_MAX_STREAM_DATA},
    {0x12, QUIC_FK_MAX_STREAMS},
    {0x13, QUIC_FK_MAX_STREAMS},
    {0x14, QUIC_FK_DATA_BLOCKED},
    {0x15, QUIC_FK_STREAM_DATA_BLOCKED},
    {0x16, QUIC_FK_STREAMS_BLOCKED},
    {0x17, QUIC_FK_STREAMS_BLOCKED},
    {0x18, QUIC_FK_NEW_CONNECTION_ID},
    {0x19, QUIC_FK_RETIRE_CONNECTION_ID},
    {0x1a, QUIC_FK_PATH_CHALLENGE},
    {0x1b, QUIC_FK_PATH_RESPONSE},
    {0x1c, QUIC_FK_CONNECTION_CLOSE},
    {0x1d, QUIC_FK_CONNECTION_CLOSE},
    {0x1e, QUIC_FK_HANDSHAKE_DONE},
    {0x30, QUIC_FK_DATAGRAM},
    {0x31, QUIC_FK_DATAGRAM}};

quic_frame_kind quic_frame_classify(u64 type) {
  usz n = sizeof(TABLE) / sizeof(TABLE[0]);
  for (usz i = 0; i < n; i++)
    if (TABLE[i].type == type) return (quic_frame_kind)TABLE[i].kind;
  return QUIC_FK_UNKNOWN;
}

/* Only ACK, PADDING, and CONNECTION_CLOSE are non-ack-eliciting. */
static int non_eliciting(quic_frame_kind k) {
  return k == QUIC_FK_PADDING || k == QUIC_FK_ACK ||
         k == QUIC_FK_CONNECTION_CLOSE;
}

int quic_frame_ack_eliciting(quic_frame_kind kind) {
  if (kind == QUIC_FK_UNKNOWN) return 0;
  return !non_eliciting(kind);
}
