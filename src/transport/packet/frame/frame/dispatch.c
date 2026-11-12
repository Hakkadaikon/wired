#include "transport/packet/frame/frame/dispatch.h"

/* Map each defined frame type value to its kind, indexed by the type itself
 * (every defined type is below 0x32; a gap or anything past the table is
 * FK_UNKNOWN = 0). STREAM (0x08-0x0f) and the paired types (ACK,
 * MAX_STREAMS, *_BLOCKED, CONNECTION_CLOSE, DATAGRAM) list each value. Runs
 * for every frame of every walk of a received payload, hence a direct index
 * rather than a search. */
static const u8 KIND_OF[] = {
    [0x00] = FK_PADDING,
    [0x01] = FK_PING,
    [0x02] = FK_ACK,
    [0x03] = FK_ACK,
    [0x04] = FK_RESET_STREAM,
    [0x05] = FK_STOP_SENDING,
    [0x06] = FK_CRYPTO,
    [0x07] = FK_NEW_TOKEN,
    [0x08] = FK_STREAM,
    [0x09] = FK_STREAM,
    [0x0a] = FK_STREAM,
    [0x0b] = FK_STREAM,
    [0x0c] = FK_STREAM,
    [0x0d] = FK_STREAM,
    [0x0e] = FK_STREAM,
    [0x0f] = FK_STREAM,
    [0x10] = FK_MAX_DATA,
    [0x11] = FK_MAX_STREAM_DATA,
    [0x12] = FK_MAX_STREAMS,
    [0x13] = FK_MAX_STREAMS,
    [0x14] = FK_DATA_BLOCKED,
    [0x15] = FK_STREAM_DATA_BLOCKED,
    [0x16] = FK_STREAMS_BLOCKED,
    [0x17] = FK_STREAMS_BLOCKED,
    [0x18] = FK_NEW_CONNECTION_ID,
    [0x19] = FK_RETIRE_CONNECTION_ID,
    [0x1a] = FK_PATH_CHALLENGE,
    [0x1b] = FK_PATH_RESPONSE,
    [0x1c] = FK_CONNECTION_CLOSE,
    [0x1d] = FK_CONNECTION_CLOSE,
    [0x1e] = FK_HANDSHAKE_DONE,
    [0x24] = FK_RESET_STREAM_AT,
    [0x30] = FK_DATAGRAM,
    [0x31] = FK_DATAGRAM};

frame_kind frame_classify(u64 type) {
  return type < sizeof KIND_OF ? (frame_kind)KIND_OF[type] : FK_UNKNOWN;
}

/* Only ACK, PADDING, and CONNECTION_CLOSE are non-ack-eliciting. */
static int non_eliciting(frame_kind k) {
  return k == FK_PADDING || k == FK_ACK || k == FK_CONNECTION_CLOSE;
}

int frame_ack_eliciting(frame_kind kind) {
  if (kind == FK_UNKNOWN) {
    return 0;
  }
  return !non_eliciting(kind);
}
