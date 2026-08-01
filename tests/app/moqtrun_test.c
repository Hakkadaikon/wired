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
  int kind; /* 1=open_bidi_stream 3=stream_send 4=send_uni
             * 5=open_uni_stream 6=stream_fin */
  wired_wt_session* s;
  u64               stream_id; /* stream_send/stream_fin only */
  int               fin;       /* stream_send only */
  u8                payload[MOQTRUN_TEST_MAX_PAYLOAD];
  usz               payload_len;
} moqtrun_test_call;

static moqtrun_test_call g_calls[MOQTRUN_TEST_MAX_CALLS];
static usz               g_n_calls;
static i64               g_next_stream_id;
/* When >0, the next N stream_send calls are recorded (so a test can still
 * see they happened) but return 0 (rejected) -- simulates the "previous
 * round not yet ACKed" refusal (srvrun.h's wired_server_wt_stream_send
 * doc) without a real QUIC stack. */
static int g_stream_send_reject_n;

static void moqtrun_test_reset(void) {
  g_n_calls              = 0;
  g_next_stream_id       = 100;
  g_stream_send_reject_n = 0;
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
  if (g_stream_send_reject_n > 0) {
    g_stream_send_reject_n--;
    return 0;
  }
  return 1;
}

/* wired_server_wt_open_uni-shaped: one-shot open+send+FIN, the primitive
 * chat's relay uses (moqtrun_relay_open_new's fin=1 branch). */
static i64 moqtrun_test_send_uni(wired_wt_session* s, quic_span payload) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(4, s, (u64)sid, 1, payload);
  return sid;
}

/* wired_server_wt_open_uni_stream-shaped: opens without FIN, the primitive
 * audio's relay uses to start a subscriber's long-lived stream
 * (moqtrun_relay_open_new's fin=0 branch). */
static i64 moqtrun_test_open_uni_stream(
    wired_wt_session* s, quic_span payload) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(5, s, (u64)sid, 0, payload);
  return sid;
}

/* wired_server_wt_stream_fin-shaped: ends stream_id with no further bytes
 * -- the primitive moqtrun_relay_append_existing uses for a bare FIN
 * (moqtrun_is_bare_fin). */
static int moqtrun_test_stream_fin(wired_wt_session* s, u64 stream_id) {
  moqtrun_test_record(6, s, stream_id, 1, quic_span_of(0, 0));
  return 1;
}

static wired_moqt_io moqtrun_test_io(void) {
  wired_moqt_io io;
  io.open_bidi_stream = moqtrun_test_open_bidi_stream;
  io.stream_send      = moqtrun_test_stream_send;
  io.send_uni         = moqtrun_test_send_uni;
  io.open_uni_stream  = moqtrun_test_open_uni_stream;
  io.stream_fin       = moqtrun_test_stream_fin;
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
      1 /* chat: publisher's one-shot stream, FIN'd */);

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
      1 /* chat: publisher's one-shot stream, FIN'd */);

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
      1 /* chat: publisher's one-shot stream, FIN'd */);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1000,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1);

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
      1 /* chat: publisher's one-shot stream, FIN'd */);

  CHECK(moqtrun_test_count_kind(4) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* An Object on the audio track's data stream (a distinct Track Alias)
 * relays only to the audio subscriber, not the chat one. Audio opens a
 * long-lived relay stream (kind 5), not chat's one-shot send_uni. */
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

  CHECK(moqtrun_test_count_kind(5) == 1);
  CHECK(moqtrun_test_last_kind(5)->s == SESS_C);
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
 * open_uni_stream call (audio's long-lived relay stream, opened without
 * FIN since the publisher's own stream has not FIN'd), unmodified
 * byte-for-byte -- the loop only changes how many Objects are validated
 * before relaying, not the relay's own transparency. */
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

  CHECK(moqtrun_test_count_kind(5) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(5);
  CHECK(sent->s == SESS_B);
  CHECK(sent->fin == 0);
  CHECK(sent->payload_len == total);
  for (usz i = 0; i < total; i++) CHECK(sent->payload[i] == stream[i]);
}

/* The audio track's real shape: moqtVoiceClient.ts's sendOpusFrame writes
 * the SUBGROUP_HEADER + first Object in ONE call, then appends further
 * Objects to the SAME stream_id in LATER calls that carry no header at
 * all. Confirms the second (header-less) call still resolves to the same
 * track and relays -- the wired_moqtrun_track data_stream_id binding this
 * exercises. */
static void test_moqtrun_data_stream_continues_across_calls_without_header(
    void) {
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

  /* First call: SUBGROUP_HEADER (audio's declared alias 2) + one Object. */
  quic_moqdata_subhdr h = {0};
  h.type                = 0x30;
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_off = 0;
  quic_moqdata_subhdr_put(quic_mspan_of(first, sizeof first), &first_off, &h);
  first[1]           = 0x02; /* Track Alias byte: audio's declared alias */
  u8        payload0 = 7;
  quic_span p0       = quic_span_of(&payload0, 1);
  quic_moqdata_obj_put(quic_mspan_of(first, sizeof first), &first_off, 0, p0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(first, first_off), 0);
  CHECK(
      moqtrun_test_count_kind(5) == 1); /* first call opens the relay stream */

  /* Second call, SAME stream_id (999): no header, just one more Object. */
  u8        second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       second_off = 0;
  u8        payload1   = 8;
  quic_span p1         = quic_span_of(&payload1, 1);
  quic_moqdata_obj_put(
      quic_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(second, second_off), 0);

  CHECK(moqtrun_test_count_kind(3) == 1); /* second call appends */
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->s == SESS_B);
  CHECK(sent->payload_len == second_off);
  for (usz i = 0; i < second_off; i++) CHECK(sent->payload[i] == second[i]);
}

/* A header-less second call on a stream_id this hub has NOT already bound
 * to a track (e.g. no first call ever arrived, or it arrived on a
 * different stream_id) relays nowhere -- offset 0 is read as a bare
 * Object, no SUBGROUP_HEADER to resolve a track from. */
static void test_moqtrun_unbound_stream_id_relays_nowhere(void) {
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

  u8        payload0 = 7;
  quic_span p0       = quic_span_of(&payload0, 1);
  u8        bare[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       bare_off = 0;
  quic_moqdata_obj_put(quic_mspan_of(bare, sizeof bare), &bare_off, 0, p0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999 /* never seen before */, quic_span_of(bare, bare_off),
      0);

  CHECK(g_n_calls == 0);
}

/* ===================== 8. audio long-lived relay stream
 * ===================== */

/* Establishes SESS_A publishing chat+audio and SESS_B subscribed to audio,
 * returning ctrl_a (SESS_A's control stream, for further PUBLISHes/data). */
static u64 moqtrun_test_setup_audio_relay(wired_moqt_hub* hub) {
  u64 ctrl_a = moqtrun_test_publish_alice(hub);
  moqtrun_test_publish_alice_audio(hub, ctrl_a);
  wired_moqt_on_session(hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      hub, SESS_B, ctrl_b, quic_span_of(sub_audio, sub_audio_n), 0);
  return ctrl_a;
}

/* The first Object relayed on the audio track opens the subscriber's relay
 * stream (open_uni_stream, not send_uni) without FIN; a second Object on the
 * SAME publisher stream_id appends to that SAME stream_id via stream_send,
 * still without FIN -- no second open_uni_stream call. */
static void test_moqtrun_audio_first_object_opens_then_appends(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  moqtrun_test_reset();
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(first, first_n), 0 /* fin */);

  CHECK(moqtrun_test_count_kind(5) == 1); /* opened, not send_uni */
  CHECK(moqtrun_test_count_kind(4) == 0);
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->fin == 0);
  u64 relay_stream_id = opened->stream_id;

  u8        payload1 = 9;
  quic_span p1       = quic_span_of(&payload1, 1);
  u8        second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       second_off = 0;
  quic_moqdata_obj_put(
      quic_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(second, second_off), 0 /* fin */);

  CHECK(moqtrun_test_count_kind(5) == 0); /* no second stream opened */
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* appended = moqtrun_test_last_kind(3);
  CHECK(appended->stream_id == relay_stream_id);
  CHECK(appended->fin == 0);
}

/* When the publisher's own stream FINs, the subscriber's relay stream is
 * closed (stream_send fin=1) in the same call -- and the NEXT Object (on a
 * fresh publisher stream_id) opens a brand new relay stream rather than
 * appending to the closed one. */
static void test_moqtrun_audio_publisher_fin_closes_and_reopens(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(first, first_n), 0 /* fin */);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(first, first_n), 1 /* fin: close */);

  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->fin == 1);
  CHECK(moqtrun_test_count_kind(5) == 0);

  /* A fresh publisher stream_id after the close opens a fresh relay
   * stream, not an append to the now-closed one. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1001, quic_span_of(first, first_n), 0 /* fin */);
  CHECK(moqtrun_test_count_kind(5) == 1);
  CHECK(moqtrun_test_count_kind(3) == 0);
}

/* Chat keeps its pre-existing one-shot-per-Object shape: every relayed chat
 * Object still goes out via send_uni (fresh stream, FIN'd immediately),
 * never open_uni_stream/stream_send -- a regression check that the audio
 * long-lived-stream path did not change chat's relay. */
static void test_moqtrun_chat_still_uses_send_uni_every_object(void) {
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
      1 /* chat's publisher stream is always one-shot, FIN'd */);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1000,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1);

  CHECK(moqtrun_test_count_kind(4) == 2);
  CHECK(moqtrun_test_count_kind(5) == 0);
  CHECK(moqtrun_test_count_kind(3) == 0);
}

/* A stream_send rejection (0 -- the previous round not yet ACKed) drops
 * that one Object silently: no crash, and the relay stream stays bound for
 * the NEXT Object, which appends normally. */
static void test_moqtrun_stream_send_rejection_drops_frame_not_fatal(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(first, first_n), 0);
  u64 relay_stream_id = moqtrun_test_last_kind(5)->stream_id;

  u8        payload1 = 9;
  quic_span p1       = quic_span_of(&payload1, 1);
  u8        second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       second_off = 0;
  quic_moqdata_obj_put(
      quic_mspan_of(second, sizeof second), &second_off, 1, p1);

  g_stream_send_reject_n = 1; /* the next stream_send call is refused */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(second, second_off), 0);
  CHECK(
      moqtrun_test_last_kind(3)->stream_id == relay_stream_id); /* attempted */

  /* a 3rd Object still appends to the SAME stream, unaffected by the
   * earlier rejection. */
  u8        payload2 = 10;
  quic_span p2       = quic_span_of(&payload2, 1);
  u8        third[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       third_off = 0;
  quic_moqdata_obj_put(quic_mspan_of(third, sizeof third), &third_off, 1, p2);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(third, third_off), 0);
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->stream_id == relay_stream_id);
  CHECK(moqtrun_test_count_kind(5) == 0); /* still no re-open */
}

/* Two subscribers to the same audio track each get their OWN relay stream
 * (distinct stream ids, both bound independently) -- confirming per-sub,
 * not per-track, send_stream_id state. */
static void test_moqtrun_audio_two_subscribers_independent_streams(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_b[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_b_n = moqtrun_test_subscribe_audio_msg(sub_b);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, quic_span_of(sub_b, sub_b_n), 0);

  wired_moqt_on_session(&hub, SESS_C, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_c[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_c_n = moqtrun_test_subscribe_audio_msg(sub_c);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, quic_span_of(sub_c, sub_c_n), 0);

  moqtrun_test_reset();
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(first, first_n), 0);

  CHECK(moqtrun_test_count_kind(5) == 2); /* one open per subscriber */
  u64 sid_b = 0, sid_c = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 5) continue;
    if (g_calls[i].s == SESS_B) sid_b = g_calls[i].stream_id;
    if (g_calls[i].s == SESS_C) sid_c = g_calls[i].stream_id;
  }
  CHECK(sid_b != 0 && sid_c != 0 && sid_b != sid_c);

  u8        payload1 = 9;
  quic_span p1       = quic_span_of(&payload1, 1);
  u8        second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       second_off = 0;
  quic_moqdata_obj_put(
      quic_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(second, second_off), 0);
  CHECK(moqtrun_test_count_kind(3) == 2); /* each subscriber's own append */
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 3) continue;
    if (g_calls[i].s == SESS_B) CHECK(g_calls[i].stream_id == sid_b);
    if (g_calls[i].s == SESS_C) CHECK(g_calls[i].stream_id == sid_c);
  }
}

/* A real browser's write()+close() can land as TWO separate wired_moqt_
 * on_stream_data calls: the message bytes (fin=0), then a byte-less
 * fin=1 call carrying only the stream's own FIN (confirmed against a real
 * WebTransport client -- see moqtrun_is_bare_fin's doc). Even for chat
 * (whose publisher stream is conceptually one-shot), the FIRST call's
 * fin=0 means it cannot yet be relayed via send_uni -- it must open the
 * subscriber's stream and wait, same as audio's first frame -- and the
 * bare-FIN second call must close that stream via stream_fin, not
 * stream_send (which never accepts an empty payload). */
static void test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes(void) {
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
      0 /* data, no fin yet */);

  CHECK(moqtrun_test_count_kind(5) == 1); /* opened, held open */
  CHECK(moqtrun_test_count_kind(4) == 0); /* not yet a one-shot send_uni */
  u64 relay_stream_id = moqtrun_test_last_kind(5)->stream_id;

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(0, 0), 1 /* bare FIN, no bytes */);

  CHECK(moqtrun_test_count_kind(6) == 1); /* stream_fin, not stream_send */
  CHECK(moqtrun_test_last_kind(6)->stream_id == relay_stream_id);
  CHECK(moqtrun_test_count_kind(3) == 0);
}

/* Same split as above, but for audio's long-lived stream mid-call: a
 * bare-FIN call on a stream that already appended at least one Object
 * still closes via stream_fin, not a rejected empty stream_send. */
static void test_moqtrun_audio_split_data_then_bare_fin_closes(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(first, first_n), 0);
  u64 relay_stream_id = moqtrun_test_last_kind(5)->stream_id;

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(0, 0), 1);

  CHECK(moqtrun_test_count_kind(6) == 1);
  CHECK(moqtrun_test_last_kind(6)->stream_id == relay_stream_id);
  CHECK(moqtrun_test_count_kind(3) == 0);

  /* The next Object (fresh publisher stream_id) opens a new relay stream,
   * confirming the closed one was actually unbound. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1001, quic_span_of(first, first_n), 0);
  CHECK(moqtrun_test_count_kind(5) == 1);
}

/* Two chat messages whose publisher streams OVERLAP: msg2's data arrives
 * before msg1's bare FIN (a real browser sends each message's data and FIN
 * as separate calls, and cross-stream delivery order is not guaranteed --
 * under concurrent voice traffic this interleaving happens routinely).
 * Each message must ride its OWN relay stream, and EACH stream must be
 * closed by its own publisher's FIN -- the pre-relay-map design bound one
 * stream per track/sub, so msg2 got appended onto msg1's still-open relay
 * stream and msg1's late FIN resolved to nothing, wedging the subscriber's
 * read-to-EOF forever (observed as near-100% chat loss with voice on). */
static void test_moqtrun_interleaved_chat_messages_close_independently(void) {
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
  /* msg1 data (fin=0, publisher stream 999) -> opens relay stream A. */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);
  CHECK(moqtrun_test_count_kind(5) == 1);
  u64 relay_a = moqtrun_test_last_kind(5)->stream_id;

  /* msg2 data (fin=0, publisher stream 1003) arrives BEFORE msg1's FIN ->
   * must open its OWN relay stream B, never append onto A. (No reset here:
   * moqtrun_test_reset would rewind the stub's stream-id counter and hand B
   * the same id as A, breaking the identity check below.) */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1003,
      quic_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);
  CHECK(moqtrun_test_count_kind(5) == 2);
  CHECK(moqtrun_test_count_kind(3) == 0); /* no append onto A */
  u64 relay_b = moqtrun_test_last_kind(5)->stream_id;
  CHECK(relay_b != relay_a);

  /* msg1's late bare FIN (999) still closes A -- not B, not nothing. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(0, 0), 1);
  CHECK(moqtrun_test_count_kind(6) == 1);
  CHECK(moqtrun_test_last_kind(6)->stream_id == relay_a);

  /* msg2's bare FIN (1003) closes B. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 1003, quic_span_of(0, 0), 1);
  CHECK(moqtrun_test_count_kind(6) == 1);
  CHECK(moqtrun_test_last_kind(6)->stream_id == relay_b);
}

/* A subscriber that joins AFTER the audio publisher's long-lived stream
 * already started (the real app's normal order: voice starts streaming the
 * moment a client connects, before any peer has subscribed) still gets a
 * relay stream -- opened late, carrying the saved SUBGROUP_HEADER alone,
 * with later rounds appending normally. Without the late open, the whole
 * call stayed silent for everyone who wasn't subscribed at the instant of
 * the very first Opus frame (observed as decodedFrameCounts=0 in e2e). */
static void test_moqtrun_late_subscriber_gets_late_opened_stream(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  /* First voice frame arrives with NO subscriber yet: nothing opens, but
   * the relay entry (and its saved header) is recorded. */
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(first, first_n), 0);
  CHECK(moqtrun_test_count_kind(5) == 0);

  /* Now SESS_B subscribes to the audio track. */
  wired_moqt_on_session(&hub, SESS_B, quic_span_of(0, 0), quic_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, quic_span_of(sub_audio, sub_audio_n), 0);

  /* Next frame (bare Object, same publisher stream): late-opens B's relay
   * stream carrying the saved SUBGROUP_HEADER alone. The header here is
   * the golden stream's first 2 bytes (Type 0x70 rewritten alias 0x02 --
   * Group ID rides mode 0b00's explicit field within those bytes for this
   * golden vector's small values). */
  u8        payload1 = 9;
  quic_span p1       = quic_span_of(&payload1, 1);
  u8        second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       second_off = 0;
  quic_moqdata_obj_put(
      quic_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(second, second_off), 0);
  CHECK(moqtrun_test_count_kind(5) == 1); /* late open, header only */
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->s == SESS_B);
  CHECK(opened->payload_len > 0);
  CHECK(opened->payload_len < first_n); /* header alone, no Objects */
  for (usz i = 0; i < opened->payload_len; i++)
    CHECK(opened->payload[i] == first[i]); /* the stream's own header bytes */
  u64 late_sid = opened->stream_id;

  /* The round after that appends to the late-opened stream normally. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(second, second_off), 0);
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->stream_id == late_sid);
  CHECK(moqtrun_test_count_kind(5) == 0);
}

/* Deliveries slice the publisher's stream at arbitrary byte positions, but
 * every relayed round must end on an Object boundary: a round dropped for
 * one subscriber (stream_send refusal) vanishes whole from that
 * subscriber's stream, and a round torn mid-Object turns every later byte
 * into mis-framed garbage (observed live as voice going permanently silent
 * while bytes kept arriving). An Object split across two deliveries is
 * therefore held back and forwarded ONLY once complete. */
static void test_moqtrun_torn_object_held_until_complete(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(first, first_n), 0);

  /* One 5-byte-payload Object, split mid-payload across two deliveries. */
  u8  payload[5] = {1, 2, 3, 4, 5};
  u8  obj[MOQTRUN_TEST_MAX_PAYLOAD];
  usz obj_n = 0;
  quic_moqdata_obj_put(
      quic_mspan_of(obj, sizeof obj), &obj_n, 1, quic_span_of(payload, 5));
  usz cut = obj_n - 3; /* tear inside the payload */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(obj, cut), 0);
  CHECK(moqtrun_test_count_kind(3) == 0); /* torn: nothing forwarded */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(obj + cut, obj_n - cut), 0);
  CHECK(moqtrun_test_count_kind(3) == 1); /* completed: forwarded whole */
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->payload_len == obj_n);
  for (usz i = 0; i < obj_n; i++) CHECK(sent->payload[i] == obj[i]);
}

/* A delivery carrying [tail of Object A][all of Object B][head of Object
 * C] forwards exactly A+B (fragment A completed by this delivery, C's head
 * held back for the next). */
static void test_moqtrun_normalize_forwards_only_whole_objects(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(first, first_n), 0);

  u8  pa[3] = {0xA, 0xA, 0xA};
  u8  pb[4] = {0xB, 0xB, 0xB, 0xB};
  u8  pc[5] = {0xC, 0xC, 0xC, 0xC, 0xC};
  u8  abc[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = 0;
  quic_moqdata_obj_put(
      quic_mspan_of(abc, sizeof abc), &n, 1, quic_span_of(pa, 3));
  usz a_end = n;
  quic_moqdata_obj_put(
      quic_mspan_of(abc, sizeof abc), &n, 1, quic_span_of(pb, 4));
  usz b_end = n;
  quic_moqdata_obj_put(
      quic_mspan_of(abc, sizeof abc), &n, 1, quic_span_of(pc, 5));
  usz cut1 = a_end - 2; /* first delivery tears inside A */
  usz cut2 = b_end + 3; /* second delivery ends inside C */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(abc, cut1), 0);
  CHECK(moqtrun_test_count_kind(3) == 0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(abc + cut1, cut2 - cut1), 0);
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->payload_len == b_end); /* A+B whole, C's head held back */
  for (usz i = 0; i < b_end; i++) CHECK(sent->payload[i] == abc[i]);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(abc + cut2, n - cut2), 0);
  CHECK(moqtrun_test_count_kind(3) == 1); /* C completes */
  sent = moqtrun_test_last_kind(3);
  CHECK(sent->payload_len == n - b_end);
  for (usz i = 0; i < n - b_end; i++) CHECK(sent->payload[i] == abc[b_end + i]);
}

/* The OPENING delivery can be torn too: header + one whole Object + the
 * head of a second. The relay stream opens carrying only the whole-Object
 * prefix; the torn head completes on the next delivery. */
static void test_moqtrun_fresh_delivery_tail_held_back(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8  wire[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_subgroup_with_alias(0x02, wire); /* header + 1 obj */
  usz whole_end = n;
  u8  p2[4]     = {9, 9, 9, 9};
  quic_moqdata_obj_put(
      quic_mspan_of(wire, sizeof wire), &n, 1, quic_span_of(p2, 4));
  usz cut = whole_end + 2; /* tear inside the 2nd Object */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, quic_span_of(wire, cut), 0);
  CHECK(moqtrun_test_count_kind(5) == 1);
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->payload_len == whole_end); /* torn tail not in the open */
  for (usz i = 0; i < whole_end; i++) CHECK(opened->payload[i] == wire[i]);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, quic_span_of(wire + cut, n - cut), 0);
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->payload_len == n - whole_end); /* the completed 2nd Object */
  for (usz i = 0; i < n - whole_end; i++)
    CHECK(sent->payload[i] == wire[whole_end + i]);
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
  test_moqtrun_data_stream_continues_across_calls_without_header();
  test_moqtrun_unbound_stream_id_relays_nowhere();
  test_moqtrun_audio_first_object_opens_then_appends();
  test_moqtrun_audio_publisher_fin_closes_and_reopens();
  test_moqtrun_chat_still_uses_send_uni_every_object();
  test_moqtrun_stream_send_rejection_drops_frame_not_fatal();
  test_moqtrun_audio_two_subscribers_independent_streams();
  test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes();
  test_moqtrun_audio_split_data_then_bare_fin_closes();
  test_moqtrun_interleaved_chat_messages_close_independently();
  test_moqtrun_late_subscriber_gets_late_opened_stream();
  test_moqtrun_torn_object_held_until_complete();
  test_moqtrun_normalize_forwards_only_whole_objects();
  test_moqtrun_fresh_delivery_tail_held_back();
}
