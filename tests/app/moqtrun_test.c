#include "app/moqt/run/moqtrun.h"

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "moqt_golden.h"
#include "test.h"

/* draft-ietf-moq-transport-19 hub relay: wires the six MOQT domains
 * onto the WT app API. The real srvrun sends (open/append) are replaced by
 * recording stubs bound through wired_moqt_io, so this test never links the
 * QUIC/TLS stack. */

/* ===================== recording io stub ===================== */

#define MOQTRUN_TEST_MAX_CALLS 32
#define MOQTRUN_TEST_MAX_PAYLOAD 256

typedef struct {
  int               kind; /* 1=open_bidi_stream 3=stream_send 4=send_uni */
  wired_wt_session* s;
  u64               stream_id; /* stream_send only */
  int               fin;       /* stream_send only */
  u8                payload[MOQTRUN_TEST_MAX_PAYLOAD];
  usz               payload_len;
} moqtrun_test_call;

static moqtrun_test_call g_calls[MOQTRUN_TEST_MAX_CALLS];
static usz               g_n_calls;
static i64               g_next_stream_id;

static void moqtrun_test_reset(void) {
  g_n_calls        = 0;
  g_next_stream_id = 100;
}

static void moqtrun_test_record(
    int kind, wired_wt_session* s, u64 stream_id, int fin, quic_span p) {
  moqtrun_test_call* c = &g_calls[g_n_calls++];
  c->kind              = kind;
  c->s                 = s;
  c->stream_id         = stream_id;
  c->fin               = fin;
  c->payload_len =
      p.n < MOQTRUN_TEST_MAX_PAYLOAD ? p.n : MOQTRUN_TEST_MAX_PAYLOAD;
  for (usz i = 0; i < c->payload_len; i++) c->payload[i] = p.p[i];
}

static i64 moqtrun_test_open_bidi_stream(
    wired_wt_session* s, quic_span payload) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(1, s, (u64)sid, 0, payload);
  return sid;
}

static int moqtrun_test_stream_send(
    wired_wt_session* s, u64 stream_id, quic_span payload, int fin) {
  moqtrun_test_record(3, s, stream_id, fin, payload);
  return 1;
}

/* wired_server_wt_open_uni-shaped: one-shot open+send+FIN, the primitive
 * moqtrun_relay_to_one uses (never open_uni_stream + a bare stream_send
 * (fin=1) -- wired_server_wt_stream_send rejects an empty payload, so that
 * shape can never actually close the stream in production). */
static i64 moqtrun_test_send_uni(wired_wt_session* s, quic_span payload) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(4, s, (u64)sid, 1, payload);
  return sid;
}

static wired_moqt_io moqtrun_test_io(void) {
  wired_moqt_io io;
  io.open_bidi_stream = moqtrun_test_open_bidi_stream;
  io.stream_send      = moqtrun_test_stream_send;
  io.send_uni         = moqtrun_test_send_uni;
  return io;
}

static usz moqtrun_test_count_kind(int kind) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == kind) n++;
  return n;
}

static const moqtrun_test_call* moqtrun_test_last_kind(int kind) {
  for (usz i = g_n_calls; i > 0; i--)
    if (g_calls[i - 1].kind == kind) return &g_calls[i - 1];
  return 0;
}

/* Fixture sessions: opaque wired_wt_session*, never dereferenced by this
 * layer (only compared/stored) -- distinct integer values stand in fine. */
static wired_wt_session* const SESS_A = (wired_wt_session*)(usz)1;
static wired_wt_session* const SESS_B = (wired_wt_session*)(usz)2;
static wired_wt_session* const SESS_C = (wired_wt_session*)(usz)3;

/* ===================== 1. session establishment ===================== */

/* Establishment leg: a fresh WT session gets one control stream
 * opened without FIN, carrying a SETUP envelope (Type 0x2F00). */
static void test_moqtrun_on_session_sends_setup(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());

  wired_moqt_on_session(&hub, SESS_A, quic_span_of(0, 0), quic_span_of(0, 0));

  CHECK(moqtrun_test_count_kind(1) == 1);
  const moqtrun_test_call* c = moqtrun_test_last_kind(1);
  CHECK(c->s == SESS_A);
  usz       off = 0;
  u64       type;
  quic_span body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_SETUP);
}

/* A second control stream for an already-tracked WT session is a no-op
 * here, not a second SETUP. srvrun's wt_on_session doc says "fires once",
 * but nothing upstream stops a duplicate/retried Extended CONNECT from
 * reaching this callback a second time for the same session -- draft 3.3
 * permits only one control stream per peer, so sending SETUP twice on one
 * WT session would itself be the violation this hub exists to prevent. */
static void test_moqtrun_on_session_twice_is_idempotent(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());

  wired_moqt_on_session(&hub, SESS_A, quic_span_of(0, 0), quic_span_of(0, 0));
  wired_moqt_on_session(&hub, SESS_A, quic_span_of(0, 0), quic_span_of(0, 0));

  CHECK(moqtrun_test_count_kind(1) == 1);
}

/* ===================== 2. PUBLISH / SUBSCRIBE ===================== */

/* PUBLISH is accepted and answered with REQUEST_OK on the control
 * stream (no FIN: the control stream stays open for later messages). */
static void test_moqtrun_publish_replies_request_ok(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_moqt_on_session(&hub, SESS_A, quic_span_of(0, 0), quic_span_of(0, 0));
  const moqtrun_test_call* opened = moqtrun_test_last_kind(1);
  u64                      ctrl   = opened->stream_id;

  wired_moqt_on_stream_data(
      &hub, SESS_A, ctrl,
      quic_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN), 0);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* c = moqtrun_test_last_kind(3);
  CHECK(c->fin == 0);
  usz       off = 0;
  u64       type;
  quic_span body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_REQUEST_OK);
}

/* Drives session A through PUBLISH so its track ("chat"/"room1"/"alice",
 * the shared golden vector) is live -- shared setup for the SUBSCRIBE
 * tests below. */
static u64 moqtrun_test_publish_alice(wired_moqt_hub* hub) {
  wired_moqt_on_session(hub, SESS_A, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_a = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      hub, SESS_A, ctrl_a,
      quic_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN), 0);
  return ctrl_a;
}

/* SUBSCRIBE naming an already-PUBLISHed track ("alice", matching
 * the golden PUBLISH's name) gets SUBSCRIBE_OK with an assigned alias. */
static void test_moqtrun_subscribe_matching_publish_replies_ok(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  const moqtrun_test_call* c = moqtrun_test_last_kind(3);
  CHECK(c->s == SESS_B);
  usz       off = 0;
  u64       type;
  quic_span body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_SUBSCRIBE_OK);
  quic_moqctl_subscribe_ok ok;
  usz                      body_off = 0;
  CHECK(quic_moqctl_subscribe_ok_take(body, &body_off, &ok) == QUIC_MOQCTL_OK);
  (void)ok; /* alias value itself is hub-assigned, not pinned */
}

/* SUBSCRIBE naming a track nobody has PUBLISHed yet gets
 * REQUEST_ERROR DOES_NOT_EXIST. */
static void test_moqtrun_subscribe_without_publish_replies_error(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_REQUEST_ERROR);
  quic_moqctl_request_error e;
  usz                       body_off = 0;
  CHECK(quic_moqctl_request_error_take(body, &body_off, &e) == QUIC_MOQCTL_OK);
  CHECK(e.error_code == QUIC_MOQCTL_ERR_DOES_NOT_EXIST);
}

/* ===================== 3. Object relay ===================== */

/* An Object arriving on a publisher's data stream
 * is relayed to one Established subscriber as exactly one fresh uni
 * stream, opened, sent, and FIN'd in a single io.send_uni call --
 * wired_server_wt_stream_send never accepts an empty payload (a FIN needs
 * a final non-empty slice to ride on), so a bare open_uni_stream + empty
 * stream_send(fin=1) can never actually close the stream in production;
 * send_uni is the primitive that does. */
static void test_moqtrun_object_relay_to_subscriber(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset(); /* only observe the relay's own calls */
  wired_moqt_on_stream_data(
      &hub, SESS_A, /* data stream id, distinct from control */ 999,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);

  CHECK(moqtrun_test_count_kind(4) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(4);
  CHECK(sent->s == SESS_B);
  CHECK(sent->fin == 1);
  CHECK(moqtrun_test_count_kind(3) == 0); /* no separate FIN append */
}

/* The relayed stream's bytes equal the publisher's original bytes,
 * unmodified (payload and framing alike). */
static void test_moqtrun_object_relay_preserves_bytes(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);

  const moqtrun_test_call* sent = moqtrun_test_last_kind(4);
  CHECK(sent->payload_len == G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN);
  for (usz i = 0; i < G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN; i++)
    CHECK(sent->payload[i] == g_moqt_data_subgroup_stream_basic[i]);
}

/* Two Established subscribers, two Objects each get their
 * own fresh uni stream per subscriber -- no stream is shared across
 * Objects or subscribers, and every stream FINs (loss-free, all
 * delivered). */
static void test_moqtrun_object_relay_two_subscribers_two_objects(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  wired_moqt_on_session(&hub, SESS_C, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1000,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);

  /* 2 subscribers * 2 Objects = 4 fresh streams, each one send_uni call
   * (open+send+FIN together), every allocated stream id distinct (no
   * reuse). */
  CHECK(moqtrun_test_count_kind(4) == 4);
  CHECK(moqtrun_test_count_kind(3) == 0);
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 4) continue;
    usz matches = 0;
    for (usz j = 0; j < g_n_calls; j++)
      if (g_calls[j].kind == 4 && g_calls[j].stream_id == g_calls[i].stream_id)
        matches++;
    CHECK(matches == 1);
  }
}

/* ===================== 4. loss-free hub defenses ===================== */

/* A SUBSCRIBE carrying a non-zero delivery-timeout parameter is
 * rejected with REQUEST_ERROR NOT_SUPPORTED, never SUBSCRIBE_OK. */
static void test_moqtrun_subscribe_nonzero_timeout_rejected(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;

  /* SUBSCRIBE with one added Message Parameter: Type 0x02
   * (OBJECT_DELIVERY_TIMEOUT, even => varint value), value 5 -- built by
   * hand since no golden vector carries this parameter (draft SS10.2
   * varint parameter encoding: Delta Type then value). */
  u8 sub_with_timeout[G_MOQT_CTL_SUBSCRIBE_BASIC_LEN + 2];
  for (usz i = 0; i < G_MOQT_CTL_SUBSCRIBE_BASIC_LEN; i++)
    sub_with_timeout[i] = g_moqt_ctl_subscribe_basic[i];
  /* index 22 is the golden's trailing Num Params byte (0x00): bump it to
   * 1, then append Delta Type 0x02, Value 0x05. */
  sub_with_timeout[22] = 0x01;
  sub_with_timeout[23] = 0x02; /* Delta Type (from 0) = 0x02 */
  sub_with_timeout[24] = 0x05; /* Value */
  usz total            = G_MOQT_CTL_SUBSCRIBE_BASIC_LEN + 2;
  /* fix up the 16-bit Message Length (bytes[1..2], was 0x0014) for the two
   * extra body bytes. */
  u16 new_len         = 0x14 + 2;
  sub_with_timeout[1] = (u8)(new_len >> 8);
  sub_with_timeout[2] = (u8)(new_len & 0xFF);

  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, quic_span_of(sub_with_timeout, total), 0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_REQUEST_ERROR);
  quic_moqctl_request_error e;
  usz                       body_off = 0;
  CHECK(quic_moqctl_request_error_take(body, &body_off, &e) == QUIC_MOQCTL_OK);
  CHECK(e.error_code == QUIC_MOQCTL_ERR_NOT_SUPPORTED);
}

/* The hub's own SUBSCRIBE_OK never carries a delivery-timeout
 * parameter (Num Params == 0 in the reply this hub builds). */
static void test_moqtrun_subscribe_ok_carries_no_timeout_param(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;

  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  quic_moqctl_peek_type(
      quic_span_of(c->payload, c->payload_len), &off, &type, &body);
  quic_moqctl_subscribe_ok ok;
  usz                      body_off = 0;
  quic_moqctl_subscribe_ok_take(body, &body_off, &ok);
  CHECK(ok.params.n == 0);
}

/* ===================== 5. unsupported / non-relay traffic
 * ===================== */

/* A First-type request this hub does not implement (using
 * GOAWAY's Type id as a stand-in "unhandled control type" since this
 * subset's ctl codec does not expose FETCH/TRACK_STATUS encoders) still
 * gets a REQUEST_ERROR NOT_SUPPORTED, not silence. GOAWAY specifically is
 * exercised separately below since it has its own mid-stream semantics. */
static void test_moqtrun_unknown_first_type_gets_not_supported(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_moqt_on_session(&hub, SESS_A, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_a = moqtrun_test_last_kind(1)->stream_id;

  /* A syntactically valid envelope with a Type this dispatch table has no
   * PUBLISH/SUBSCRIBE/GOAWAY entry for: REQUEST_OK (0x7), empty body. */
  u8 msg[3] = {0x07, 0x00, 0x00};
  wired_moqt_on_stream_data(
      &hub, SESS_A, ctrl_a, quic_span_of(msg, sizeof msg), 0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_REQUEST_ERROR);
}

/* A GOAWAY on a request stream (here: the shared control stream,
 * standing in for "a stream other than the very first SETUP exchange") is
 * accepted without the hub emitting any close/reply traffic of its own --
 * distinguishing it from a protocol violation the session layer would
 * have to act on. */
static void test_moqtrun_goaway_on_request_stream_produces_no_reply(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_moqt_on_session(&hub, SESS_A, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_a = moqtrun_test_last_kind(1)->stream_id;

  moqtrun_test_reset();
  quic_moqctl_goaway g = {0};
  u8                 buf[16];
  usz                off = 0;
  quic_moqctl_goaway_encode(quic_mspan_of(buf, sizeof buf), &off, &g);
  wired_moqt_on_stream_data(&hub, SESS_A, ctrl_a, quic_span_of(buf, off), 0);

  CHECK(g_n_calls == 0);
}

/* A padding stream's bytes are discarded -- no relay, no reply. */
static void test_moqtrun_padding_stream_discarded(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(g_moqt_data_stream_type_padding, 5), 0);

  CHECK(g_n_calls == 0);
}

void test_moqtrun(void) {
  test_moqtrun_on_session_sends_setup();
  test_moqtrun_on_session_twice_is_idempotent();
  test_moqtrun_publish_replies_request_ok();
  test_moqtrun_subscribe_matching_publish_replies_ok();
  test_moqtrun_subscribe_without_publish_replies_error();
  test_moqtrun_object_relay_to_subscriber();
  test_moqtrun_object_relay_preserves_bytes();
  test_moqtrun_object_relay_two_subscribers_two_objects();
  test_moqtrun_subscribe_nonzero_timeout_rejected();
  test_moqtrun_subscribe_ok_carries_no_timeout_param();
  test_moqtrun_unknown_first_type_gets_not_supported();
  test_moqtrun_goaway_on_request_stream_produces_no_reply();
  test_moqtrun_padding_stream_discarded();
}
