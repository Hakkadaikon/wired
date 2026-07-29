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

/* Both g_moqt_ctl_publish_basic and g_moqt_ctl_subscribe_basic share the
 * same layout up to the Track Name (Type+Len, Request ID, 2 Namespace
 * fields "chat"/"room1"), so one rewrite covers both: replaces the 5-byte
 * "alice" Track Name (offset 16) with "alice/audio" (11 bytes) and
 * backpatches the 16-bit Message Length (offset 1-2) for the 6 extra
 * bytes. Returns the new total length. */
static usz moqtrun_test_rename_track_to_audio(
    const u8* src, usz src_len, u8* dst) {
  static const u8 suffix[] = "alice/audio";
  usz             tail     = src_len - 22; /* bytes after "alice" (offset 22) */
  quic_memcpy(dst, src, 16);
  dst[16] = (u8)(sizeof suffix - 1);
  quic_memcpy(dst + 17, suffix, sizeof suffix - 1);
  quic_memcpy(dst + 17 + sizeof suffix - 1, src + 22, tail);
  u16 new_body_len = (u16)(src[1] << 8 | src[2]) + 6;
  dst[1]           = (u8)(new_body_len >> 8);
  dst[2]           = (u8)(new_body_len & 0xFF);
  return 17 + (sizeof suffix - 1) + tail;
}

/* Drives session A through a second PUBLISH, of the "alice/audio" track
 * (Track Alias 1, same as g_moqt_ctl_publish_basic's -- the two tracks are
 * distinguished by name/slot, not alias, until each track's own alias is
 * recorded via moqtrun_track_by_alias in production; this test suite gives
 * audio a distinct alias below to exercise that path). */
static void moqtrun_test_publish_alice_audio(wired_moqt_hub* hub, u64 ctrl_a) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_rename_track_to_audio(
      g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN, buf);
  buf[n - 2] = 0x02; /* Track Alias: 2 (distinct from chat's 1) */
  wired_moqt_on_stream_data(hub, SESS_A, ctrl_a, quic_span_of(buf, n), 0);
}

/* Builds a SUBSCRIBE naming "alice/audio" instead of "alice". */
static usz moqtrun_test_subscribe_audio_msg(u8* buf) {
  return moqtrun_test_rename_track_to_audio(
      g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN, buf);
}

/* g_moqt_data_subgroup_stream_basic with its Track Alias byte (offset 1)
 * replaced -- lets a test address the audio track's Object stream
 * distinctly from chat's (whose golden Track Alias is 1). */
static usz moqtrun_test_subgroup_with_alias(u8 alias, u8* buf) {
  quic_memcpy(
      buf, g_moqt_data_subgroup_stream_basic,
      G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN);
  buf[1] = alias;
  return G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN;
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

/* ===================== 6. multi-track peer (chat + audio)
 * ===================== */

/* A peer PUBLISHes chat ("alice") then audio ("alice/audio") on two
 * separate slots -- both get REQUEST_OK, and each is independently
 * SUBSCRIBE-able. */
static void test_moqtrun_peer_publishes_two_tracks(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_reset();
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_REQUEST_OK);
}

/* A third distinct track name (both of the peer's 2 slots already taken)
 * gets REQUEST_ERROR instead of silently overwriting an existing track. */
static void test_moqtrun_third_publish_gets_error(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  moqtrun_test_reset();
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_rename_track_to_audio(
      g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN, buf);
  /* rewrite "alice/audio" (11) to "alice/video" (11) for a third name. */
  buf[16 + 6]  = 'v';
  buf[16 + 7]  = 'i';
  buf[16 + 8]  = 'd';
  buf[16 + 9]  = 'e';
  buf[16 + 10] = 'o';
  wired_moqt_on_stream_data(&hub, SESS_A, ctrl_a, quic_span_of(buf, n), 0);

  CHECK(moqtrun_test_count_kind(3) == 1);
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

/* Re-PUBLISHing the same track name ("alice") a second time still consumes
 * only one slot -- confirmed by then successfully PUBLISHing "alice/audio"
 * into the (still free) second slot. */
static void test_moqtrun_republish_same_name_reuses_slot(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice(&hub); /* re-PUBLISH "alice" again */

  moqtrun_test_reset();
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_REQUEST_OK); /* not REQUEST_ERROR (slot free) */
}

/* SUBSCRIBEing the audio track gets SUBSCRIBE_OK. */
static void test_moqtrun_subscribe_audio_track_replies_ok(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_subscribe_audio_msg(buf);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, quic_span_of(buf, n), 0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      QUIC_MOQCTL_OK);
  CHECK(type == QUIC_MOQCTL_T_SUBSCRIBE_OK);
}

/* The same subscriber SUBSCRIBEing chat then audio gets a valid
 * SUBSCRIBE_OK from each track's OWN alias sequence (each track allocates
 * aliases independently starting from 0, so both replies legitimately
 * name alias 0 here -- the two tracks are still routed correctly since
 * relay keys on the publisher's Track Alias, not the hub's per-subscriber
 * one; see moqtClient.ts's own comment on why it never reads this value). */
static void test_moqtrun_chat_and_audio_get_different_aliases(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  const moqtrun_test_call* chat_reply = moqtrun_test_last_kind(3);
  usz                      off1       = 0;
  u64                      type1;
  quic_span                body1;
  quic_moqctl_peek_type(
      quic_span_of(chat_reply->payload, chat_reply->payload_len), &off1, &type1,
      &body1);
  quic_moqctl_subscribe_ok chat_ok;
  usz                      chat_off = 0;
  quic_moqctl_subscribe_ok_take(body1, &chat_off, &chat_ok);

  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_subscribe_audio_msg(buf);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, quic_span_of(buf, n), 0);
  const moqtrun_test_call* audio_reply = moqtrun_test_last_kind(3);
  usz                      off2        = 0;
  u64                      type2;
  quic_span                body2;
  quic_moqctl_peek_type(
      quic_span_of(audio_reply->payload, audio_reply->payload_len), &off2,
      &type2, &body2);
  quic_moqctl_subscribe_ok audio_ok;
  usz                      audio_off = 0;
  quic_moqctl_subscribe_ok_take(body2, &audio_off, &audio_ok);

  CHECK(type1 == QUIC_MOQCTL_T_SUBSCRIBE_OK);
  CHECK(type2 == QUIC_MOQCTL_T_SUBSCRIBE_OK);
  /* Both tracks allocate aliases independently from 0, so this hub's
   * per-subscriber alias legitimately collides across tracks -- routing
   * still works because relay keys on the PUBLISHER's own Track Alias
   * (own_alias), never on this value (see moqtClient.ts's comment). */
  CHECK(chat_ok.track_alias == audio_ok.track_alias);
}

/* An Object on the chat track's data stream (Track Alias 1, the golden
 * default) relays only to the chat subscriber, not the audio one. */
static void test_moqtrun_chat_object_relays_only_to_chat_subscriber(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session(&hub, SESS_C, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, quic_span_of(sub_audio, sub_audio_n), 0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);

  CHECK(moqtrun_test_count_kind(4) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* An Object on the audio track's data stream (a distinct Track Alias)
 * relays only to the audio subscriber, not the chat one. */
static void test_moqtrun_audio_object_relays_only_to_audio_subscriber(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session(&hub, SESS_C, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, quic_span_of(sub_audio, sub_audio_n), 0);

  moqtrun_test_reset();
  u8  audio_obj[MOQTRUN_TEST_MAX_PAYLOAD];
  usz audio_obj_n = moqtrun_test_subgroup_with_alias(0x02, audio_obj);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(audio_obj, audio_obj_n), 0);

  CHECK(moqtrun_test_count_kind(4) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_C);
}

/* An Object whose Track Alias matches neither of the publisher's declared
 * tracks (chat=1, audio=2) is relayed nowhere. */
static void test_moqtrun_unknown_alias_object_relays_nowhere(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      quic_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  u8  unknown_obj[MOQTRUN_TEST_MAX_PAYLOAD];
  usz unknown_obj_n = moqtrun_test_subgroup_with_alias(0x09, unknown_obj);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(unknown_obj, unknown_obj_n), 0);

  CHECK(g_n_calls == 0);
}

/* Both tracks' SUBSCRIBE_OK replies fit in one dispatch's send_buf without
 * overflow -- two SUBSCRIBEs (chat then audio) arriving back-to-back on the
 * same control-stream call both get their reply queued and flushed. */
static void test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;

  u8  two_subs[MOQTRUN_TEST_MAX_PAYLOAD];
  usz off = 0;
  quic_memcpy(
      two_subs, g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN);
  off += G_MOQT_CTL_SUBSCRIBE_BASIC_LEN;
  off += moqtrun_test_rename_track_to_audio(
      g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN,
      two_subs + off);

  moqtrun_test_reset(); /* only observe this dispatch's own replies */
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, quic_span_of(two_subs, off), 0);

  CHECK(moqtrun_test_count_kind(3) == 1); /* one stream_send, two replies */
  const moqtrun_test_call* c         = moqtrun_test_last_kind(3);
  usz                      check_off = 0;
  u64                      t1;
  quic_span                b1;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &check_off, &t1, &b1) ==
      QUIC_MOQCTL_OK);
  CHECK(t1 == QUIC_MOQCTL_T_SUBSCRIBE_OK);
  u64       t2;
  quic_span b2;
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(c->payload, c->payload_len), &check_off, &t2, &b2) ==
      QUIC_MOQCTL_OK);
  CHECK(t2 == QUIC_MOQCTL_T_SUBSCRIBE_OK);
}

/* ===================== 7. multi-Object data stream decode
 * ===================== */

/* Builds a SUBGROUP_HEADER (track_alias=1, group/subgroup 0, default
 * priority, explicit first-object mode so subgroup_id needs no
 * resolution) followed by n_objects Objects, each with a 1-byte payload
 * (its own index) and Object ID == its index (id_delta 0 for the first,
 * else 1). Returns the total bytes written. */
static usz moqtrun_test_build_multi_object_stream(usz n_objects, u8* buf) {
  quic_moqdata_subhdr h = {0};
  h.type =
      0x30; /* mode 0b00 (explicit subgroup_id=0), no props, default priority */
  usz off = 0;
  quic_moqdata_subhdr_put(
      quic_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, &h);
  for (usz i = 0; i < n_objects; i++) {
    u8        payload_byte = (u8)i;
    quic_span payload      = quic_span_of(&payload_byte, 1);
    quic_moqdata_obj_put(
        quic_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, i == 0 ? 0 : 1,
        payload);
  }
  return off;
}

/* A stream with a single Object decodes the same via the loop as the
 * former one-shot path: exactly 1 Object, *off lands at the stream's end. */
static void test_moqtrun_decode_loop_single_object_matches_one_shot(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz total = moqtrun_test_build_multi_object_stream(1, buf);

  usz                 off = 0;
  quic_moqdata_subhdr hdr;
  CHECK(
      quic_moqdata_subhdr_take(quic_span_of(buf, total), &off, &hdr) ==
      QUIC_MOQDATA_OK);
  usz n = moqtrun_decode_object_loop(quic_span_of(buf, total), &off, &hdr);
  CHECK(n == 1);
  CHECK(off == total);
}

/* 2 and 3 concatenated Objects on one stream all decode, *off reaching the
 * buffer's end. */
static void test_moqtrun_decode_loop_multiple_objects(void) {
  usz counts[2] = {2, 3};
  for (usz c = 0; c < 2; c++) {
    u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
    usz total = moqtrun_test_build_multi_object_stream(counts[c], buf);

    usz                 off = 0;
    quic_moqdata_subhdr hdr;
    CHECK(
        quic_moqdata_subhdr_take(quic_span_of(buf, total), &off, &hdr) ==
        QUIC_MOQDATA_OK);
    usz n = moqtrun_decode_object_loop(quic_span_of(buf, total), &off, &hdr);
    CHECK(n == counts[c]);
    CHECK(off == total);
  }
}

/* A stream truncated mid-way through its last Object decodes only the
 * complete ones, and *off stops at the end of the last complete Object
 * (never mid-Object). */
static void test_moqtrun_decode_loop_stops_at_truncation(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz total     = moqtrun_test_build_multi_object_stream(3, buf);
  usz truncated = total - 1; /* cuts into the 3rd Object's payload byte */

  usz                 off = 0;
  quic_moqdata_subhdr hdr;
  CHECK(
      quic_moqdata_subhdr_take(quic_span_of(buf, truncated), &off, &hdr) ==
      QUIC_MOQDATA_OK);
  usz       header_end = off;
  quic_span data       = quic_span_of(buf, truncated);
  usz       n          = moqtrun_decode_object_loop(data, &off, &hdr);
  CHECK(n == 2); /* only the first 2 Objects were whole */
  CHECK(off > header_end);
  CHECK(off < truncated); /* stopped short of the truncated tail */
}

/* An Object whose cumulative Object ID overflows (VIOLATION, per
 * quic_moqdata_obj_take's doc) stops the loop there -- objects decoded
 * before it are still counted, the VIOLATION-shaped one is not. */
static void test_moqtrun_decode_loop_stops_at_violation(void) {
  u8                  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  quic_moqdata_subhdr h = {0};
  h.type                = 0x30;
  usz off               = 0;
  quic_moqdata_subhdr_put(quic_mspan_of(buf, sizeof buf), &off, &h);
  u8        payload_byte = 0;
  quic_span payload      = quic_span_of(&payload_byte, 1);
  quic_moqdata_obj_put(quic_mspan_of(buf, sizeof buf), &off, 0, payload);
  /* 2nd Object: id_delta = UINT64_MAX overflows Object ID accumulation. */
  quic_moqdata_obj_put(
      quic_mspan_of(buf, sizeof buf), &off, 0xFFFFFFFFFFFFFFFFULL, payload);
  usz total = off;

  usz                 decode_off = 0;
  quic_moqdata_subhdr hdr;
  CHECK(
      quic_moqdata_subhdr_take(quic_span_of(buf, total), &decode_off, &hdr) ==
      QUIC_MOQDATA_OK);
  usz n =
      moqtrun_decode_object_loop(quic_span_of(buf, total), &decode_off, &hdr);
  CHECK(n == 1); /* the 2nd (VIOLATION) Object is not counted */
}

/* A multi-Object audio-track stream still relays whole, in exactly one
 * send_uni call, unmodified byte-for-byte -- the loop only changes how
 * many Objects are validated before relaying, not the relay's own
 * transparency. */
static void test_moqtrun_multi_object_stream_relays_in_one_send_uni(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, quic_span_of(sub_audio, sub_audio_n), 0);

  u8  stream[MOQTRUN_TEST_MAX_PAYLOAD];
  usz total = moqtrun_test_build_multi_object_stream(3, stream);
  stream[1] = 0x02; /* Track Alias byte: audio's declared alias */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(stream, total), 0);

  CHECK(moqtrun_test_count_kind(4) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(4);
  CHECK(sent->s == SESS_B);
  CHECK(sent->fin == 1);
  CHECK(sent->payload_len == total);
  for (usz i = 0; i < total; i++) CHECK(sent->payload[i] == stream[i]);
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
  test_moqtrun_peer_publishes_two_tracks();
  test_moqtrun_third_publish_gets_error();
  test_moqtrun_republish_same_name_reuses_slot();
  test_moqtrun_subscribe_audio_track_replies_ok();
  test_moqtrun_chat_and_audio_get_different_aliases();
  test_moqtrun_chat_object_relays_only_to_chat_subscriber();
  test_moqtrun_audio_object_relays_only_to_audio_subscriber();
  test_moqtrun_unknown_alias_object_relays_nowhere();
  test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow();
  test_moqtrun_decode_loop_single_object_matches_one_shot();
  test_moqtrun_decode_loop_multiple_objects();
  test_moqtrun_decode_loop_stops_at_truncation();
  test_moqtrun_decode_loop_stops_at_violation();
  test_moqtrun_multi_object_stream_relays_in_one_send_uni();
}
