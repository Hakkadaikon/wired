#include "transport/packet/frame/pipeline/framewalk.h"

#include "app/datagram/datagram/datagram.h"
#include "test.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/flowctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/ncid.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* RFC 9000 12.4: the walker yields each frame's type in order across a mix of
 * single-byte and length-bearing frames. */
static void test_framewalk_sequence(void) {
  u8  buf[64];
  usz n = 0;
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);
  quic_crypto_frame cf = {.offset = 0, .length = 3, .data = (const u8*)"abc"};
  n += quic_frame_put_crypto(buf + n, sizeof(buf) - n, &cf);
  quic_stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 2,
      .data      = (const u8*)"hi",
      .fin       = 1};
  n += quic_frame_put_stream(buf + n, sizeof(buf) - n, &sf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PADDING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);

  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING && fr.start == buf && fr.remaining == n);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_CRYPTO);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK((fr.type & 0xf8) == QUIC_FRAME_STREAM_BASE);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PADDING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* An unmeasurable frame type stops the walk rather than misreading bytes. */
static void test_framewalk_unmeasurable(void) {
  u8             buf[1] = {0x21}; /* not a defined frame type (RFC 9000 19) */
  quic_framewalk it;
  quic_framewalk_init(&it, buf, sizeof(buf));
  quic_framewalk_item fr;
  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* RFC 9221 5 regression: a 0x31 (explicit Length) DATAGRAM frame followed by
 * another frame must be measured correctly, so the walk continues to see the
 * second frame rather than truncating the rest of the packet. */
static void test_framewalk_datagram_len_then_ping(void) {
  u8                  buf[64];
  usz                 n  = 0;
  quic_datagram_frame df = {.length = 3, .data = (const u8*)"xyz"};
  n += quic_datagram_encode(quic_mspan_of(buf + n, sizeof(buf) - n), &df, 1);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_DATAGRAM_LEN);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* RFC 9221 5: a 0x30 (no Length) DATAGRAM frame consumes the rest of the
 * packet, as it must be the last frame. */
static void test_framewalk_datagram_no_len_consumes_rest(void) {
  u8                  buf[64];
  usz                 n  = 0;
  quic_datagram_frame df = {.length = 5, .data = (const u8*)"hello"};
  n += quic_datagram_encode(quic_mspan_of(buf + n, sizeof(buf) - n), &df, 0);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_DATAGRAM);
  CHECK(fr.remaining == n);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* RFC 9000 19.4/19.5, draft-ietf-quic-reliable-stream-reset: RESET_STREAM,
 * STOP_SENDING, and RESET_STREAM_AT must each be measured (not treated as
 * unmeasurable), so a payload coalescing one of them with a following frame
 * lets the walk continue instead of stopping. */
static void test_framewalk_reset_stream_then_ping(void) {
  u8                      buf[64];
  usz                     n  = 0;
  quic_reset_stream_frame rf = {
      .stream_id = 4, .error_code = 1, .final_size = 0};
  n += quic_reset_stream_encode(buf + n, sizeof(buf) - n, &rf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_RESET_STREAM);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

static void test_framewalk_stop_sending_then_ping(void) {
  u8                      buf[64];
  usz                     n  = 0;
  quic_stop_sending_frame sf = {.stream_id = 4, .error_code = 2};
  n += quic_stop_sending_encode(buf + n, sizeof(buf) - n, &sf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_STOP_SENDING);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

static void test_framewalk_reset_stream_at_then_ping(void) {
  u8                         buf[64];
  usz                        n  = 0;
  quic_reset_stream_at_frame rf = {
      .stream_id = 4, .error_code = 3, .final_size = 10, .reliable_size = 5};
  n += quic_reset_stream_at_encode(buf + n, sizeof(buf) - n, &rf);
  n += quic_frame_put_simple(buf + n, sizeof(buf) - n, QUIC_FRAME_PING);

  quic_framewalk it;
  quic_framewalk_init(&it, buf, n);
  quic_framewalk_item fr;

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_RESET_STREAM_AT);

  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);

  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* Walk buf/n and assert it yields exactly [want_type, PING] then ends. */
static void fw_check_then_ping(const u8* buf, usz n, u64 want_type) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, buf, n);
  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == want_type);
  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_PING);
  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

/* RFC 9000 19.7/19.9-19.18 regression: every flow-control and connection-
 * management frame a real peer coalesces with request STREAM frames must be
 * measurable, or the walk stops and the rest of the packet -- including
 * STREAM/ACK frames -- is silently dropped while note_app_rx still ACKs the
 * pn (permanent data loss: the peer never retransmits). quic-go coalesces
 * NEW_CONNECTION_ID with the first request's STREAM frames right after the
 * handshake, which is how the http3 interop test hit this. */
static void test_framewalk_flow_frames_then_ping(void) {
  u8  buf[64];
  usz n;

  n = quic_max_data_encode(buf, sizeof buf, &(quic_data_frame){77});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_MAX_DATA);

  n = quic_data_blocked_encode(buf, sizeof buf, &(quic_data_frame){77});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_DATA_BLOCKED);

  n = quic_max_stream_data_encode(
      buf, sizeof buf, &(quic_stream_data_frame){4, 524288});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_MAX_STREAM_DATA);

  n = quic_stream_data_blocked_encode(
      buf, sizeof buf, &(quic_stream_data_frame){4, 524288});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_STREAM_DATA_BLOCKED);

  n = quic_max_streams_encode(buf, sizeof buf, &(quic_streams_frame){10, 0});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_MAX_STREAMS_BIDI);

  n = quic_max_streams_encode(buf, sizeof buf, &(quic_streams_frame){10, 1});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_MAX_STREAMS_UNI);

  n = quic_streams_blocked_encode(
      buf, sizeof buf, &(quic_streams_frame){10, 0});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_STREAMS_BLOCKED_BIDI);

  n = quic_streams_blocked_encode(
      buf, sizeof buf, &(quic_streams_frame){10, 1});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_STREAMS_BLOCKED_UNI);
}

static void test_framewalk_conn_frames_then_ping(void) {
  u8       buf[64];
  usz      n;
  const u8 pathdata[QUIC_PATH_DATA] = {1, 2, 3, 4, 5, 6, 7, 8};

  n = quic_new_token_encode(
      buf, sizeof buf, &(quic_new_token_frame){5, (const u8*)"token"});
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_NEW_TOKEN);

  n = quic_retire_cid_encode(buf, sizeof buf, 7);
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_RETIRE_CID);

  n = quic_path_encode(buf, sizeof buf, QUIC_FRAME_PATH_CHALLENGE, pathdata);
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_PATH_CHALLENGE);

  n = quic_path_encode(buf, sizeof buf, QUIC_FRAME_PATH_RESPONSE, pathdata);
  n += quic_frame_put_simple(buf + n, sizeof buf - n, QUIC_FRAME_PING);
  fw_check_then_ping(buf, n, QUIC_FRAME_PATH_RESPONSE);
}

/* The exact real-world shape: NEW_CONNECTION_ID coalesced ahead of a request
 * STREAM frame. The STREAM frame must still be reachable by the walk. */
static void test_framewalk_ncid_then_stream(void) {
  u8              buf[96];
  usz             n;
  quic_ncid_frame nf = {.seq = 1, .retire_prior_to = 0, .cid_len = 8};
  for (usz i = 0; i < 8; i++) nf.cid[i] = (u8)i;
  for (usz i = 0; i < QUIC_NCID_TOKEN; i++) nf.token[i] = (u8)(0x40 + i);
  n = quic_ncid_encode(buf, sizeof buf, &nf);
  CHECK(n > 0);
  quic_stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 2,
      .data      = (const u8*)"hi",
      .fin       = 1};
  n += quic_frame_put_stream(buf + n, sizeof buf - n, &sf);

  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, buf, n);
  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK(fr.type == QUIC_FRAME_NEW_CID);
  CHECK(quic_framewalk_next(&it, &fr) == 1);
  CHECK((fr.type & 0xf8) == QUIC_FRAME_STREAM_BASE);
  CHECK(quic_framewalk_next(&it, &fr) == 0);
}

void test_framewalk(void) {
  test_framewalk_sequence();
  test_framewalk_unmeasurable();
  test_framewalk_datagram_len_then_ping();
  test_framewalk_datagram_no_len_consumes_rest();
  test_framewalk_reset_stream_then_ping();
  test_framewalk_stop_sending_then_ping();
  test_framewalk_reset_stream_at_then_ping();
  test_framewalk_flow_frames_then_ping();
  test_framewalk_conn_frames_then_ping();
  test_framewalk_ncid_then_stream();
}
