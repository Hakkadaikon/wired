#include "transport/packet/frame/pipeline/framewalk.h"

#include "app/datagram/datagram/datagram.h"
#include "common/bytes/varint/varint.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/frame/flowctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/ncid.h"
#include "transport/packet/frame/frame/stream_ctl.h"

void quic_framewalk_init(quic_framewalk* it, const u8* frames, usz len) {
  it->cur       = frames;
  it->remaining = len;
}

/* RFC 9000 19.3/19.6/19.8/19.19, RFC 9221 5: each measurable multi-byte kind's
 * length comes from its own decoder, which returns total bytes consumed. */
static usz ack_len(const u8* buf, usz n) {
  quic_ack_frame f;
  return quic_ack_decode(buf, n, &f);
}
static usz crypto_len(const u8* buf, usz n) {
  quic_crypto_frame f;
  return quic_frame_get_crypto(buf, n, &f);
}
static usz stream_len(const u8* buf, usz n) {
  quic_stream_frame f;
  return quic_frame_get_stream(buf, n, &f);
}
static usz conn_close_len(const u8* buf, usz n) {
  quic_conn_close_frame f;
  return quic_frame_get_conn_close(buf, n, &f);
}
/* RFC 9221 5: type 0x30 has no Length field and runs to the end of the packet;
 * type 0x31 carries an explicit Length varint. quic_datagram_decode already
 * returns total bytes consumed for either shape, so the walker need not
 * re-derive the varint arithmetic. */
static usz datagram_len(const u8* buf, usz n) {
  quic_datagram_frame f;
  return quic_datagram_decode(buf, n, &f);
}
/* RFC 9000 19.4/19.5, draft-ietf-quic-reliable-stream-reset: these three
 * stream-control kinds share the same decode-returns-bytes-consumed shape as
 * the frames above, so the walker can skip over them like any other
 * measurable frame instead of stalling when one is coalesced with other
 * frames in the same payload. */
static usz reset_stream_len(const u8* buf, usz n) {
  quic_reset_stream_frame f;
  return quic_reset_stream_decode(buf, n, &f);
}
static usz stop_sending_len(const u8* buf, usz n) {
  quic_stop_sending_frame f;
  return quic_stop_sending_decode(buf, n, &f);
}
static usz reset_stream_at_len(const u8* buf, usz n) {
  quic_reset_stream_at_frame f;
  return quic_reset_stream_at_decode(buf, n, &f);
}
/* RFC 9000 19.7/19.9-19.18: the flow-control and connection-management
 * frames a real peer coalesces with STREAM/ACK frames. Each reuses its own
 * decoder's bytes-consumed return, same shape as the frames above -- without
 * a row here the walk stops at the frame and everything after it in the
 * packet is dropped while the pn still gets ACKed (permanent data loss). */
static usz max_data_len(const u8* buf, usz n) {
  quic_data_frame f;
  return quic_max_data_decode(buf, n, &f);
}
static usz data_blocked_len(const u8* buf, usz n) {
  quic_data_frame f;
  return quic_data_blocked_decode(buf, n, &f);
}
static usz max_stream_data_len(const u8* buf, usz n) {
  quic_stream_data_frame f;
  return quic_max_stream_data_decode(buf, n, &f);
}
static usz stream_data_blocked_len(const u8* buf, usz n) {
  quic_stream_data_frame f;
  return quic_stream_data_blocked_decode(buf, n, &f);
}
static usz max_streams_len(const u8* buf, usz n) {
  quic_streams_frame f;
  return quic_max_streams_decode(buf, n, &f);
}
static usz streams_blocked_len(const u8* buf, usz n) {
  quic_streams_frame f;
  return quic_streams_blocked_decode(buf, n, &f);
}
static usz new_token_len(const u8* buf, usz n) {
  quic_new_token_frame f;
  return quic_new_token_decode(buf, n, &f);
}
static usz ncid_len(const u8* buf, usz n) {
  quic_ncid_frame f;
  return quic_ncid_decode(buf, n, &f);
}
static usz retire_cid_len(const u8* buf, usz n) {
  u64 seq;
  return quic_retire_cid_decode(buf, n, &seq);
}
static usz path_challenge_len(const u8* buf, usz n) {
  u8 data[QUIC_PATH_DATA];
  return quic_path_decode(buf, n, QUIC_FRAME_PATH_CHALLENGE, data);
}
static usz path_response_len(const u8* buf, usz n) {
  u8 data[QUIC_PATH_DATA];
  return quic_path_decode(buf, n, QUIC_FRAME_PATH_RESPONSE, data);
}

/* Single-byte kinds (PADDING/PING/HANDSHAKE_DONE) have no table row; they are
 * measured before the lookup (see frame_len, single_byte below). */
typedef usz (*len_fn)(const u8*, usz);
typedef struct {
  u8     kind;
  len_fn fn;
} len_row;
static const len_row LEN_TABLE[] = {
    {QUIC_FK_ACK, ack_len},
    {QUIC_FK_CRYPTO, crypto_len},
    {QUIC_FK_STREAM, stream_len},
    {QUIC_FK_CONNECTION_CLOSE, conn_close_len},
    {QUIC_FK_DATAGRAM, datagram_len},
    {QUIC_FK_RESET_STREAM, reset_stream_len},
    {QUIC_FK_STOP_SENDING, stop_sending_len},
    {QUIC_FK_RESET_STREAM_AT, reset_stream_at_len},
    {QUIC_FK_MAX_DATA, max_data_len},
    {QUIC_FK_DATA_BLOCKED, data_blocked_len},
    {QUIC_FK_MAX_STREAM_DATA, max_stream_data_len},
    {QUIC_FK_STREAM_DATA_BLOCKED, stream_data_blocked_len},
    {QUIC_FK_MAX_STREAMS, max_streams_len},
    {QUIC_FK_STREAMS_BLOCKED, streams_blocked_len},
    {QUIC_FK_NEW_TOKEN, new_token_len},
    {QUIC_FK_NEW_CONNECTION_ID, ncid_len},
    {QUIC_FK_RETIRE_CONNECTION_ID, retire_cid_len},
    {QUIC_FK_PATH_CHALLENGE, path_challenge_len},
    {QUIC_FK_PATH_RESPONSE, path_response_len},
};

/* Length of a frame the walker measures via a decoder, or 0 if kind has no
 * table row (an unmeasurable kind). */
static usz decoded_len(quic_frame_kind kind, const u8* buf, usz n) {
  usz i, rows = sizeof LEN_TABLE / sizeof LEN_TABLE[0];
  for (i = 0; i < rows; i++)
    if (LEN_TABLE[i].kind == kind) return LEN_TABLE[i].fn(buf, n);
  return 0;
}

/* Single-byte frames carry no body (RFC 9000 19.1/19.2/19.20). */
static int single_byte(quic_frame_kind kind) {
  return kind == QUIC_FK_PADDING || kind == QUIC_FK_PING ||
         kind == QUIC_FK_HANDSHAKE_DONE;
}

/* Bytes the frame at buf occupies, or 0 if the walker cannot measure it. */
static usz frame_len(u64 type, const u8* buf, usz n) {
  quic_frame_kind kind = quic_frame_classify(type);
  if (single_byte(kind)) return 1;
  return decoded_len(kind, buf, n);
}

/* Measure the frame at the cursor, validating it fits. Returns its length or 0.
 */
static usz measure(const quic_framewalk* it, u64* type) {
  usz len;
  if (quic_varint_decode(it->cur, it->remaining, type) == 0) return 0;
  len = frame_len(*type, it->cur, it->remaining);
  return len > it->remaining ? 0 : len;
}

int quic_framewalk_next(quic_framewalk* it, quic_framewalk_item* out) {
  usz len;
  if (it->remaining == 0) return 0;
  len = measure(it, &out->type);
  if (len == 0) return 0;
  out->start     = it->cur;
  out->remaining = it->remaining;
  it->cur += len;
  it->remaining -= len;
  return 1;
}
