#include "app/moqt/run/moqtrun.h"

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "common/bytes/util/ct.h"
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
             * 5=open_uni_stream 6=stream_fin 7=stream_reset
             * 8=send_uni2 9=send_datagram */
  wired_wt_session* s;
  u64               stream_id; /* stream_send/stream_fin/stream_reset only */
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
/* When set, every stream_send addressed to THIS session is rejected (while
 * other sessions' sends succeed) -- lets a test starve one subscriber
 * without touching its peers. */
static wired_wt_session* g_stream_send_reject_sess;
/* stream_reset's stubbed return: 1 (queued) by default; 0 simulates the
 * SDK's reset latch being full this step (wired_server_wt_stream_reset). */
static int g_stream_reset_ret;
/* When >0, the next N send_uni calls are recorded but return -1 (refused)
 * -- simulates send-slot/stream-limit exhaustion on the receiver's
 * connection (wired_server_wt_open_uni's failure return). */
static int g_send_uni_fail_n;
/* When set, every send_uni addressed to THIS session returns -1 (while
 * other sessions' sends succeed) -- the send_uni twin of
 * g_stream_send_reject_sess, for pinning per-subscriber independence at
 * chat's fan-out scale (test_moqtrun_chat_one_of_three_subscribers_
 * refused). */
static wired_wt_session* g_send_uni_reject_sess;
/* send_uni2's twins of the two send_uni knobs above: fail the next N calls
 * outright, or refuse every call addressed to one session. */
static int               g_send_uni2_fail_n;
static wired_wt_session* g_send_uni2_reject_sess;
/* When set, every send_datagram addressed to THIS session returns 0
 * (refused) while other sessions' sends succeed -- the datagram twin of
 * g_send_uni_reject_sess. */
static wired_wt_session* g_send_dg_reject_sess;

static void moqtrun_test_reset(void) {
  g_n_calls                 = 0;
  g_next_stream_id          = 100;
  g_stream_send_reject_n    = 0;
  g_stream_send_reject_sess = 0;
  g_stream_reset_ret        = 1;
  g_send_uni_fail_n         = 0;
  g_send_uni_reject_sess    = 0;
  g_send_uni2_fail_n        = 0;
  g_send_uni2_reject_sess   = 0;
  g_send_dg_reject_sess     = 0;
}

static void moqtrun_test_record(
    int kind, wired_wt_session* s, u64 stream_id, int fin, wired_span p) {
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
    wired_wt_session* s, wired_span payload) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(1, s, (u64)sid, 0, payload);
  return sid;
}

static int moqtrun_test_stream_send(
    wired_wt_session* s, u64 stream_id, wired_span payload, int fin) {
  moqtrun_test_record(3, s, stream_id, fin, payload);
  if (g_stream_send_reject_n > 0) {
    g_stream_send_reject_n--;
    return 0;
  }
  if (g_stream_send_reject_sess && s == g_stream_send_reject_sess) return 0;
  return 1;
}

/* wired_server_wt_open_uni-shaped: one-shot open+send+FIN, the primitive
 * chat's relay uses (moqtrun_relay_open_new's fin=1 branch). */
static i64 moqtrun_test_send_uni(wired_wt_session* s, wired_span payload) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(4, s, (u64)sid, 1, payload);
  if (g_send_uni_fail_n > 0) {
    g_send_uni_fail_n--;
    return -1;
  }
  if (g_send_uni_reject_sess && s == g_send_uni_reject_sess) return -1;
  return sid;
}

/* io.send_uni2-shaped: one-shot open+send+FIN of head||body, the primitive
 * the hub's live track uses. Records head||body as one call (truncated to
 * the recorder's buffer; payload_len keeps the TRUE total so a test can
 * still check the real length -- never read payload past
 * MOQTRUN_TEST_MAX_PAYLOAD). */
static i64 moqtrun_test_send_uni2(
    wired_wt_session* s, wired_span head, wired_span body) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(8, s, (u64)sid, 1, head);
  moqtrun_test_call* c    = &g_calls[g_n_calls - 1];
  usz                room = MOQTRUN_TEST_MAX_PAYLOAD - c->payload_len;
  usz                take = body.n < room ? body.n : room;
  for (usz i = 0; i < take; i++) c->payload[c->payload_len + i] = body.p[i];
  c->payload_len = head.n + body.n; /* true length, buffer may be shorter */
  if (g_send_uni2_fail_n > 0) {
    g_send_uni2_fail_n--;
    return -1;
  }
  if (g_send_uni2_reject_sess && s == g_send_uni2_reject_sess) return -1;
  return sid;
}

/* wired_server_wt_open_uni_stream-shaped: opens without FIN, the primitive
 * audio's relay uses to start a subscriber's long-lived stream
 * (moqtrun_relay_open_new's fin=0 branch). */
static i64 moqtrun_test_open_uni_stream(
    wired_wt_session* s, wired_span payload) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(5, s, (u64)sid, 0, payload);
  return sid;
}

/* wired_server_wt_stream_fin-shaped: ends stream_id with no further bytes
 * -- the primitive moqtrun_relay_append_existing uses for a bare FIN
 * (moqtrun_is_bare_fin). */
static int moqtrun_test_stream_fin(wired_wt_session* s, u64 stream_id) {
  moqtrun_test_record(6, s, stream_id, 1, wired_span_of(0, 0));
  return 1;
}

/* wired_server_wt_stream_reset-shaped: abandons stream_id (the primitive
 * the busy-streak shed uses, moqtrun_relay_shed_one). Returns
 * g_stream_reset_ret so a test can simulate the SDK refusing (latch full). */
static int moqtrun_test_stream_reset(
    wired_wt_session* s, u64 stream_id, u32 error_code) {
  (void)error_code;
  moqtrun_test_record(7, s, stream_id, 0, wired_span_of(0, 0));
  return g_stream_reset_ret;
}

/* wired_server_wt_send_datagram_to-shaped: queues one datagram (the
 * primitive wired_moqt_on_datagram's fan-out uses). Returns 0 (refused)
 * for the session named by g_send_dg_reject_sess, 1 otherwise. */
static int moqtrun_test_send_datagram(wired_wt_session* s, wired_span payload) {
  moqtrun_test_record(9, s, 0, 0, payload);
  if (g_send_dg_reject_sess && s == g_send_dg_reject_sess) return 0;
  return 1;
}

/* wired_server_wt_stream_hold-shaped: records the publisher-credit
 * hold/release calls the reliable relay makes (the hold value rides the
 * recorder's fin field). */
static int moqtrun_test_stream_hold(
    wired_wt_session* s, u64 stream_id, int hold) {
  moqtrun_test_record(10, s, stream_id, hold, wired_span_of(0, 0));
  return 1;
}

static wired_moqt_io moqtrun_test_io(void) {
  wired_moqt_io io;
  io.open_bidi_stream = moqtrun_test_open_bidi_stream;
  io.stream_send      = moqtrun_test_stream_send;
  io.send_uni         = moqtrun_test_send_uni;
  io.open_uni_stream  = moqtrun_test_open_uni_stream;
  io.stream_fin       = moqtrun_test_stream_fin;
  io.stream_reset     = moqtrun_test_stream_reset;
  io.send_uni2        = moqtrun_test_send_uni2;
  io.send_datagram    = moqtrun_test_send_datagram;
  io.stream_hold      = moqtrun_test_stream_hold;
  io.send_budget      = 0; /* default: unconstrained, like a table without */
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
static wired_wt_session* const SESS_D = (wired_wt_session*)(usz)4;

/* ===================== 1. session establishment ===================== */

/* Establishment leg: a fresh WT session gets one control stream
 * opened without FIN, carrying a SETUP envelope (Type 0x2F00). */
static void test_moqtrun_on_session_sends_setup(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());

  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));

  CHECK(moqtrun_test_count_kind(1) == 1);
  const moqtrun_test_call* c = moqtrun_test_last_kind(1);
  CHECK(c->s == SESS_A);
  usz        off = 0;
  u64        type;
  wired_span body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_SETUP);
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

  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));

  CHECK(moqtrun_test_count_kind(1) == 1);
}

/* ===================== 2. PUBLISH / SUBSCRIBE ===================== */

/* PUBLISH is accepted and answered with REQUEST_OK on the control
 * stream (no FIN: the control stream stays open for later messages). */
static void test_moqtrun_publish_replies_request_ok(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  const moqtrun_test_call* opened = moqtrun_test_last_kind(1);
  u64                      ctrl   = opened->stream_id;

  wired_moqt_on_stream_data(
      &hub, SESS_A, ctrl,
      wired_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN), 0);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* c = moqtrun_test_last_kind(3);
  CHECK(c->fin == 0);
  usz        off = 0;
  u64        type;
  wired_span body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_OK);
}

/* Drives session A through PUBLISH so its track ("chat"/"room1"/"alice",
 * the shared golden vector) is live -- shared setup for the SUBSCRIBE
 * tests below. */
static u64 moqtrun_test_publish_alice(wired_moqt_hub* hub) {
  wired_moqt_on_session(hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_a = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      hub, SESS_A, ctrl_a,
      wired_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN), 0);
  return ctrl_a;
}

/* Both g_moqt_ctl_publish_basic and g_moqt_ctl_subscribe_basic share the
 * same layout up to the Track Name (Type+Len, Request ID, 2 Namespace
 * fields "chat"/"room1"), so one rewrite covers both: replaces the 5-byte
 * "alice" Track Name (length byte at offset 16, bytes at 17) with the
 * given name and backpatches the 16-bit Message Length (offset 1-2) by
 * name_len - 5. Returns the new total length. */
static usz moqtrun_test_rename_track(
    const u8* src, usz src_len, const u8* name, usz name_len, u8* dst) {
  usz tail = src_len - 22; /* bytes after "alice" (offset 22) */
  bytes_memcpy(dst, src, 16);
  dst[16] = (u8)name_len;
  bytes_memcpy(dst + 17, name, name_len);
  bytes_memcpy(dst + 17 + name_len, src + 22, tail);
  u16 new_body_len = (u16)((u16)(src[1] << 8 | src[2]) + name_len - 5);
  dst[1]           = (u8)(new_body_len >> 8);
  dst[2]           = (u8)(new_body_len & 0xFF);
  return 17 + name_len + tail;
}

static usz moqtrun_test_rename_track_to_audio(
    const u8* src, usz src_len, u8* dst) {
  static const u8 suffix[11] = {'a', 'l', 'i', 'c', 'e', '/',
                                'a', 'u', 'd', 'i', 'o'};
  return moqtrun_test_rename_track(src, src_len, suffix, 11, dst);
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
  wired_moqt_on_stream_data(hub, SESS_A, ctrl_a, wired_span_of(buf, n), 0);
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
  bytes_memcpy(
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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  const moqtrun_test_call* c = moqtrun_test_last_kind(3);
  CHECK(c->s == SESS_B);
  usz        off = 0;
  u64        type;
  wired_span body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_SUBSCRIBE_OK);
  moqctl_subscribe_ok ok;
  usz                 body_off = 0;
  CHECK(moqctl_subscribe_ok_take(body, &body_off, &ok) == MOQCTL_OK);
  (void)ok; /* alias value itself is hub-assigned, not pinned */
}

/* SUBSCRIBE naming a track nobody has PUBLISHed yet gets
 * REQUEST_ERROR DOES_NOT_EXIST. */
static void test_moqtrun_subscribe_without_publish_replies_error(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  wired_span               body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_ERROR);
  moqctl_request_error e;
  usz                  body_off = 0;
  CHECK(moqctl_request_error_take(body, &body_off, &e) == MOQCTL_OK);
  CHECK(e.error_code == MOQCTL_ERR_DOES_NOT_EXIST);
}

/* Local twin of moqtrun_test_last_reply_type (defined later in this file,
 * after the blob-track tests) so this earlier test does not forward-
 * reference it in the same translation unit. */
static u64 mtsub_last_reply_type(void) {
  const moqtrun_test_call* c = moqtrun_test_last_kind(3);
  if (!c) return 0;
  usz        off = 0;
  u64        type;
  wired_span body;
  if (moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
      MOQCTL_OK)
    return 0;
  return type;
}

/* draft-ietf-moq-transport-19 13.1 relays SHOULD bound subscription state:
 * a track's subs[] slot table is fixed at WIRED_MOQTRUN_MAX_SUBS -- one per
 * possible other peer. Every other peer the hub can hold subscribes to the
 * same track and each gets SUBSCRIBE_OK: the table fits the whole room
 * exactly, and a peer re-sending SUBSCRIBE keeps its one slot rather than
 * eating a second (test_moqtrun_duplicate_subscribe_reuses_slot), so no
 * live peer is ever refused for lack of a slot. */
static void test_moqtrun_subscribe_fits_every_other_peer(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);

  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    moqtrun_test_reset();
    wired_wt_session* s = (wired_wt_session*)(usz)(100 + i);
    wired_moqt_on_session(&hub, s, wired_span_of(0, 0), wired_span_of(0, 0));
    u64 ctrl = moqtrun_test_last_kind(1)->stream_id;
    wired_moqt_on_stream_data(
        &hub, s, ctrl,
        wired_span_of(
            g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
        0);
    CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  }
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
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset(); /* only observe the relay's own calls */
  wired_moqt_on_stream_data(
      &hub, SESS_A, /* data stream id, distinct from control */ 999,
      wired_span_of(
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
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  wired_moqt_on_session(&hub, SESS_C, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1 /* chat: publisher's one-shot stream, FIN'd */);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1000,
      wired_span_of(
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
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
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
      &hub, SESS_B, ctrl_b, wired_span_of(sub_with_timeout, total), 0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  wired_span               body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_ERROR);
  moqctl_request_error e;
  usz                  body_off = 0;
  CHECK(moqctl_request_error_take(body, &body_off, &e) == MOQCTL_OK);
  CHECK(e.error_code == MOQCTL_ERR_NOT_SUPPORTED);
}

/* The hub's own SUBSCRIBE_OK never carries a delivery-timeout
 * parameter (Num Params == 0 in the reply this hub builds). */
static void test_moqtrun_subscribe_ok_carries_no_timeout_param(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;

  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  wired_span               body;
  moqctl_peek_type(
      wired_span_of(c->payload, c->payload_len), &off, &type, &body);
  moqctl_subscribe_ok ok;
  usz                 body_off = 0;
  moqctl_subscribe_ok_take(body, &body_off, &ok);
  CHECK(ok.params.n == 0);
}

/* ===================== 4b. subscriber authorization (draft SS13.3)
 * ===================== */

/* Golden SUBSCRIBE with one AUTHORIZATION TOKEN parameter (draft SS10.2.2:
 * Type 0x03, Length-prefixed Token bytes) appended: Num Params (offset 22)
 * becomes 1 and the 16-bit Message Length is backpatched. */
static usz mtauth_subscribe_with_token(u8* dst, const u8* tok, usz n) {
  bytes_memcpy(dst, g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN);
  dst[22] = 0x01;
  dst[23] = 0x03; /* Type Delta from 0 = AUTHORIZATION TOKEN */
  dst[24] = (u8)n;
  bytes_memcpy(dst + 25, tok, n);
  u16 len = (u16)(G_MOQT_CTL_SUBSCRIBE_BASIC_MSG_LEN + 2 + n);
  dst[1]  = (u8)(len >> 8);
  dst[2]  = (u8)(len & 0xFF);
  return G_MOQT_CTL_SUBSCRIBE_BASIC_LEN + 2 + n;
}

/* Recording authorizer: counts calls, remembers what it was shown, answers
 * mtauth_allow. token==0 is remembered as type (u64)-1. */
static int mtauth_allow;
static u64 mtauth_seen_type;
static usz mtauth_seen_value_len;
static usz mtauth_seen_name_len;
static int mtauth_authorize(
    void* ctx, const moqctl_ftn* name, const moqctl_token* token) {
  *(int*)ctx += 1;
  mtauth_seen_name_len  = name->name.n;
  mtauth_seen_type      = token ? token->token_type : (u64)-1;
  mtauth_seen_value_len = token ? token->value.n : 0;
  return mtauth_allow;
}

static u64 mtauth_last_error_code(void) {
  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  wired_span               body;
  moqctl_request_error     e;
  usz                      body_off = 0;
  if (moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) !=
      MOQCTL_OK)
    return (u64)-1;
  if (type != MOQCTL_T_REQUEST_ERROR) return (u64)-1;
  if (moqctl_request_error_take(body, &body_off, &e) != MOQCTL_OK)
    return (u64)-1;
  return e.error_code;
}

static usz mtauth_active_subs(const wired_moqtrun_track* t) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) n += t->subs[i].active != 0;
  return n;
}

/* draft SS13.3: a relay verifies the presented token before granting a
 * subscription. With an authorizer installed, every SUBSCRIBE is shown to
 * it (Full Track Name + the USE_VALUE token, or no token): a refusal is
 * REQUEST_ERROR UNAUTHORIZED with no sub slot consumed; an acceptance is
 * SUBSCRIBE_OK as before. */
static void test_moqtrun_subscribe_requires_authorization(void) {
  static const u8 tok[] = {0x03, 0x01, 'o', 'k'};
  u8              msg[MOQTRUN_TEST_MAX_PAYLOAD];
  int             calls = 0;
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  hub.authorize_subscribe = mtauth_authorize;
  hub.authorize_ctx       = &calls;
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;

  mtauth_allow = 0;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  CHECK(calls == 1);
  CHECK(mtauth_seen_name_len == 5); /* "alice" */
  CHECK(mtauth_seen_type == (u64)-1);
  CHECK(mtauth_last_error_code() == MOQCTL_ERR_UNAUTHORIZED);
  CHECK(mtauth_active_subs(&hub.peers[0].tracks[0]) == 0);

  mtauth_allow = 1;
  moqtrun_test_reset();
  usz n = mtauth_subscribe_with_token(msg, tok, sizeof tok);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, wired_span_of(msg, n), 0);
  CHECK(calls == 2);
  CHECK(mtauth_seen_type == 1);
  CHECK(mtauth_seen_value_len == 2);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mtauth_active_subs(&hub.peers[0].tracks[0]) == 1);
}

/* draft SS10.2.2 / SS10.3.1.3: this hub never advertises
 * MAX_AUTH_TOKEN_CACHE_SIZE, so its token cache is 0 bytes and Alias-based
 * Tokens (REGISTER here) cannot be honoured: the request is refused with
 * MALFORMED_AUTH_TOKEN even on an open hub, and no sub slot is consumed. */
static void test_moqtrun_subscribe_alias_token_rejected(void) {
  static const u8 reg[] = {0x01, 0x07, 0x01, 'x'};
  u8              msg[MOQTRUN_TEST_MAX_PAYLOAD];
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;

  usz n = mtauth_subscribe_with_token(msg, reg, sizeof reg);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, wired_span_of(msg, n), 0);
  CHECK(mtauth_last_error_code() == MOQCTL_ERR_MALFORMED_AUTH_TOKEN);
  CHECK(mtauth_active_subs(&hub.peers[0].tracks[0]) == 0);
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
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_a = moqtrun_test_last_kind(1)->stream_id;

  /* A syntactically valid envelope with a Type this dispatch table has no
   * PUBLISH/SUBSCRIBE/GOAWAY entry for: REQUEST_OK (0x7), empty body. */
  u8 msg[3] = {0x07, 0x00, 0x00};
  wired_moqt_on_stream_data(
      &hub, SESS_A, ctrl_a, wired_span_of(msg, sizeof msg), 0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  wired_span               body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_ERROR);
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
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_a = moqtrun_test_last_kind(1)->stream_id;

  moqtrun_test_reset();
  moqctl_goaway g = {0};
  u8            buf[16];
  usz           off = 0;
  moqctl_goaway_encode(wired_mspan_of(buf, sizeof buf), &off, &g);
  wired_moqt_on_stream_data(&hub, SESS_A, ctrl_a, wired_span_of(buf, off), 0);

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
      &hub, SESS_A, 999, wired_span_of(g_moqt_data_stream_type_padding, 5), 0);

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
  wired_span               body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_OK);
}

/* Renames the golden PUBLISH/SUBSCRIBE template to "alice/screen" --
 * screen-sharing's own track name, distinct from "alice/audio". */
static usz moqtrun_test_rename_track_to_screen(
    const u8* src, usz src_len, u8* dst) {
  static const u8 suffix[12] = {'a', 'l', 'i', 'c', 'e', '/',
                                's', 'c', 'r', 'e', 'e', 'n'};
  return moqtrun_test_rename_track(src, src_len, suffix, 12, dst);
}

/* Drives session A through a third PUBLISH, of the "alice/screen" track
 * (a distinct Track Alias, mirroring moqtrun_test_publish_alice_audio). */
static void moqtrun_test_publish_alice_screen(wired_moqt_hub* hub, u64 ctrl_a) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_rename_track_to_screen(
      g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN, buf);
  buf[n - 2] = 0x03; /* Track Alias: 3 (distinct from chat's 1, audio's 2) */
  wired_moqt_on_stream_data(hub, SESS_A, ctrl_a, wired_span_of(buf, n), 0);
}

/* Builds a SUBSCRIBE naming "alice/screen" instead of "alice"/"alice/audio". */
static usz moqtrun_test_subscribe_screen_msg(u8* buf) {
  return moqtrun_test_rename_track_to_screen(
      g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN, buf);
}

/* One peer PUBLISHes all 3 tracks the chat app now uses in one session --
 * chat, audio, and screen -- and every one of the three gets its own
 * REQUEST_OK, proving the per-peer limit (raised to 3) actually fits a
 * screen-share alongside chat+audio with no production-code change. */
static void test_moqtrun_peer_publishes_three_tracks(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  moqtrun_test_reset();
  moqtrun_test_publish_alice_screen(&hub, ctrl_a);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  wired_span               body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_OK);
}

/* A fourth distinct track name (all 3 of the peer's slots already taken:
 * chat, audio, video/screen) gets REQUEST_ERROR instead of silently
 * overwriting an existing track. The third PUBLISH ("alice/video") must
 * succeed first -- this is what proves the per-peer limit is 3, not 2. */
static void test_moqtrun_fourth_publish_gets_error(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  moqtrun_test_reset();
  u8  buf3[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n3 = moqtrun_test_rename_track_to_audio(
      g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN, buf3);
  /* rewrite "alice/audio" (11) to "alice/video" (11) for a third name. */
  buf3[16 + 6]  = 'v';
  buf3[16 + 7]  = 'i';
  buf3[16 + 8]  = 'd';
  buf3[16 + 9]  = 'e';
  buf3[16 + 10] = 'o';
  wired_moqt_on_stream_data(&hub, SESS_A, ctrl_a, wired_span_of(buf3, n3), 0);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* c3   = moqtrun_test_last_kind(3);
  usz                      off3 = 0;
  u64                      type3;
  wired_span               body3;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c3->payload, c3->payload_len), &off3, &type3, &body3) ==
      MOQCTL_OK);
  CHECK(type3 == MOQCTL_T_REQUEST_OK);

  moqtrun_test_reset();
  u8  buf4[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n4 = moqtrun_test_rename_track_to_audio(
      g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN, buf4);
  /* rewrite "alice/audio" (11) to "alice/scren" (11) for a fourth name. */
  buf4[16 + 6]  = 's';
  buf4[16 + 7]  = 'c';
  buf4[16 + 8]  = 'r';
  buf4[16 + 9]  = 'e';
  buf4[16 + 10] = 'n';
  wired_moqt_on_stream_data(&hub, SESS_A, ctrl_a, wired_span_of(buf4, n4), 0);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* c4   = moqtrun_test_last_kind(3);
  usz                      off4 = 0;
  u64                      type4;
  wired_span               body4;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c4->payload, c4->payload_len), &off4, &type4, &body4) ==
      MOQCTL_OK);
  CHECK(type4 == MOQCTL_T_REQUEST_ERROR);
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
  wired_span               body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_REQUEST_OK); /* not REQUEST_ERROR (slot free) */
}

/* SUBSCRIBEing the audio track gets SUBSCRIBE_OK. */
static void test_moqtrun_subscribe_audio_track_replies_ok(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_subscribe_audio_msg(buf);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, wired_span_of(buf, n), 0);

  const moqtrun_test_call* c   = moqtrun_test_last_kind(3);
  usz                      off = 0;
  u64                      type;
  wired_span               body;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
      MOQCTL_OK);
  CHECK(type == MOQCTL_T_SUBSCRIBE_OK);
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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  const moqtrun_test_call* chat_reply = moqtrun_test_last_kind(3);
  usz                      off1       = 0;
  u64                      type1;
  wired_span               body1;
  moqctl_peek_type(
      wired_span_of(chat_reply->payload, chat_reply->payload_len), &off1,
      &type1, &body1);
  moqctl_subscribe_ok chat_ok;
  usz                 chat_off = 0;
  moqctl_subscribe_ok_take(body1, &chat_off, &chat_ok);

  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_subscribe_audio_msg(buf);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, wired_span_of(buf, n), 0);
  const moqtrun_test_call* audio_reply = moqtrun_test_last_kind(3);
  usz                      off2        = 0;
  u64                      type2;
  wired_span               body2;
  moqctl_peek_type(
      wired_span_of(audio_reply->payload, audio_reply->payload_len), &off2,
      &type2, &body2);
  moqctl_subscribe_ok audio_ok;
  usz                 audio_off = 0;
  moqctl_subscribe_ok_take(body2, &audio_off, &audio_ok);

  CHECK(type1 == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(type2 == MOQCTL_T_SUBSCRIBE_OK);
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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session(&hub, SESS_C, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, wired_span_of(sub_audio, sub_audio_n), 0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1 /* chat: publisher's one-shot stream, FIN'd */);

  CHECK(moqtrun_test_count_kind(4) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* C3 (S3 chat-loss investigation, tasks/moqt-voice-stability-plan.md):
 * the field's 4-client room means one chat Object commonly has THREE
 * subscribers (every other participant), a fan-out no existing test
 * exercised (the pre-existing tests here all use one or two SESS_*). A
 * real 1%-loss run showed a chat message missing from every one of its
 * receivers simultaneously (e.g. msg:user3:10 absent for user1, user2, AND
 * user4 alike) -- this pins that moqtrun's own fan-out logic (
 * moqtrun_relay_object's for-loop over track->subs[]) reaches all three
 * unconditionally, ruling out a hub-side "stops after N subscribers" bug
 * as the cause of that all-receivers-missing pattern. */
static void test_moqtrun_chat_object_relays_to_all_three_subscribers(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);

  wired_wt_session* subs[3] = {SESS_B, SESS_C, SESS_D};
  for (usz i = 0; i < 3; i++) {
    wired_moqt_on_session(
        &hub, subs[i], wired_span_of(0, 0), wired_span_of(0, 0));
    u64 ctrl = moqtrun_test_last_kind(1)->stream_id;
    wired_moqt_on_stream_data(
        &hub, subs[i], ctrl,
        wired_span_of(
            g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
        0);
  }

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1 /* chat: publisher's one-shot stream, FIN'd */);

  CHECK(moqtrun_test_count_kind(4) == 3); /* one send_uni per subscriber */
  int seen_b = 0, seen_c = 0, seen_d = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 4) continue;
    if (g_calls[i].s == SESS_B) seen_b = 1;
    if (g_calls[i].s == SESS_C) seen_c = 1;
    if (g_calls[i].s == SESS_D) seen_d = 1;
  }
  CHECK(seen_b && seen_c && seen_d);
}

/* Same fan-out, but the MIDDLE subscriber's send_uni is refused (send-slot
 * exhaustion on just that connection): the other two still receive their
 * copy, and the loss is counted (stat_open_drop), never silent -- the
 * per-subscriber independence moqtrun_relay_to_one's own doc promises,
 * now checked at 3-way fan-out instead of the existing 2-way audio test's
 * scale (test_moqtrun_audio_two_subscribers_independent_streams). */
static void test_moqtrun_chat_one_of_three_subscribers_refused(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);

  wired_wt_session* subs[3] = {SESS_B, SESS_C, SESS_D};
  for (usz i = 0; i < 3; i++) {
    wired_moqt_on_session(
        &hub, subs[i], wired_span_of(0, 0), wired_span_of(0, 0));
    u64 ctrl = moqtrun_test_last_kind(1)->stream_id;
    wired_moqt_on_stream_data(
        &hub, subs[i], ctrl,
        wired_span_of(
            g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
        0);
  }

  moqtrun_test_reset();
  g_send_uni_reject_sess = SESS_C; /* only C's send_uni is refused */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1);

  CHECK(moqtrun_test_count_kind(4) == 3); /* all three attempted */
  CHECK(hub.stat_open_drop == 1);         /* exactly C's loss is counted */
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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session(&hub, SESS_C, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, wired_span_of(sub_audio, sub_audio_n), 0);

  moqtrun_test_reset();
  u8  audio_obj[MOQTRUN_TEST_MAX_PAYLOAD];
  usz audio_obj_n = moqtrun_test_subgroup_with_alias(0x02, audio_obj);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(audio_obj, audio_obj_n), 0);

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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  u8  unknown_obj[MOQTRUN_TEST_MAX_PAYLOAD];
  usz unknown_obj_n = moqtrun_test_subgroup_with_alias(0x09, unknown_obj);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(unknown_obj, unknown_obj_n), 0);

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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;

  u8  two_subs[MOQTRUN_TEST_MAX_PAYLOAD];
  usz off = 0;
  bytes_memcpy(
      two_subs, g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN);
  off += G_MOQT_CTL_SUBSCRIBE_BASIC_LEN;
  off += moqtrun_test_rename_track_to_audio(
      g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN,
      two_subs + off);

  moqtrun_test_reset(); /* only observe this dispatch's own replies */
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(two_subs, off), 0);

  CHECK(moqtrun_test_count_kind(3) == 1); /* one stream_send, two replies */
  const moqtrun_test_call* c         = moqtrun_test_last_kind(3);
  usz                      check_off = 0;
  u64                      t1;
  wired_span               b1;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &check_off, &t1, &b1) ==
      MOQCTL_OK);
  CHECK(t1 == MOQCTL_T_SUBSCRIBE_OK);
  u64        t2;
  wired_span b2;
  CHECK(
      moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &check_off, &t2, &b2) ==
      MOQCTL_OK);
  CHECK(t2 == MOQCTL_T_SUBSCRIBE_OK);
}

/* ===================== 7. multi-Object data stream decode
 * ===================== */

/* Builds a SUBGROUP_HEADER (track_alias=1, group/subgroup 0, default
 * priority, explicit first-object mode so subgroup_id needs no
 * resolution) followed by n_objects Objects, each with a 1-byte payload
 * (its own index) and Object ID == its index (id_delta 0 for the first,
 * else 1). Returns the total bytes written. */
static usz moqtrun_test_build_multi_object_stream(usz n_objects, u8* buf) {
  moqdata_subhdr h = {0};
  h.type =
      0x30; /* mode 0b00 (explicit subgroup_id=0), no props, default priority */
  usz off = 0;
  moqdata_subhdr_put(wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, &h);
  for (usz i = 0; i < n_objects; i++) {
    u8         payload_byte = (u8)i;
    wired_span payload      = wired_span_of(&payload_byte, 1);
    moqdata_obj_put(
        wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, i == 0 ? 0 : 1,
        payload);
  }
  return off;
}

/* A stream with a single Object decodes the same via the loop as the
 * former one-shot path: exactly 1 Object, *off lands at the stream's end. */
static void test_moqtrun_decode_loop_single_object_matches_one_shot(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz total = moqtrun_test_build_multi_object_stream(1, buf);

  usz            off = 0;
  moqdata_subhdr hdr;
  CHECK(
      moqdata_subhdr_take(wired_span_of(buf, total), &off, &hdr) == MOQDATA_OK);
  usz n = moqtrun_decode_object_loop(wired_span_of(buf, total), &off, &hdr);
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

    usz            off = 0;
    moqdata_subhdr hdr;
    CHECK(
        moqdata_subhdr_take(wired_span_of(buf, total), &off, &hdr) ==
        MOQDATA_OK);
    usz n = moqtrun_decode_object_loop(wired_span_of(buf, total), &off, &hdr);
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

  usz            off = 0;
  moqdata_subhdr hdr;
  CHECK(
      moqdata_subhdr_take(wired_span_of(buf, truncated), &off, &hdr) ==
      MOQDATA_OK);
  usz        header_end = off;
  wired_span data       = wired_span_of(buf, truncated);
  usz        n          = moqtrun_decode_object_loop(data, &off, &hdr);
  CHECK(n == 2); /* only the first 2 Objects were whole */
  CHECK(off > header_end);
  CHECK(off < truncated); /* stopped short of the truncated tail */
}

/* An Object whose cumulative Object ID overflows (VIOLATION, per
 * moqdata_obj_take's doc) stops the loop there -- objects decoded
 * before it are still counted, the VIOLATION-shaped one is not. */
static void test_moqtrun_decode_loop_stops_at_violation(void) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqdata_subhdr h = {0};
  h.type           = 0x30;
  usz off          = 0;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  u8         payload_byte = 0;
  wired_span payload      = wired_span_of(&payload_byte, 1);
  moqdata_obj_put(wired_mspan_of(buf, sizeof buf), &off, 0, payload);
  /* 2nd Object: id_delta = UINT64_MAX overflows Object ID accumulation. */
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, 0xFFFFFFFFFFFFFFFFULL, payload);
  usz total = off;

  usz            decode_off = 0;
  moqdata_subhdr hdr;
  CHECK(
      moqdata_subhdr_take(wired_span_of(buf, total), &decode_off, &hdr) ==
      MOQDATA_OK);
  usz n =
      moqtrun_decode_object_loop(wired_span_of(buf, total), &decode_off, &hdr);
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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(sub_audio, sub_audio_n), 0);

  u8  stream[MOQTRUN_TEST_MAX_PAYLOAD];
  usz total = moqtrun_test_build_multi_object_stream(3, stream);
  stream[1] = 0x02; /* Track Alias byte: audio's declared alias */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(stream, total), 0);

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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(sub_audio, sub_audio_n), 0);

  /* First call: SUBGROUP_HEADER (audio's declared alias 2) + one Object. */
  moqdata_subhdr h = {0};
  h.type           = 0x30;
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_off = 0;
  moqdata_subhdr_put(wired_mspan_of(first, sizeof first), &first_off, &h);
  first[1]            = 0x02; /* Track Alias byte: audio's declared alias */
  u8         payload0 = 7;
  wired_span p0       = wired_span_of(&payload0, 1);
  moqdata_obj_put(wired_mspan_of(first, sizeof first), &first_off, 0, p0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_off), 0);
  CHECK(
      moqtrun_test_count_kind(5) == 1); /* first call opens the relay stream */

  /* Second call, SAME stream_id (999): no header, just one more Object. */
  u8         second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        second_off = 0;
  u8         payload1   = 8;
  wired_span p1         = wired_span_of(&payload1, 1);
  moqdata_obj_put(wired_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(second, second_off), 0);

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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(sub_audio, sub_audio_n), 0);

  u8         payload0 = 7;
  wired_span p0       = wired_span_of(&payload0, 1);
  u8         bare[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        bare_off = 0;
  moqdata_obj_put(wired_mspan_of(bare, sizeof bare), &bare_off, 0, p0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999 /* never seen before */, wired_span_of(bare, bare_off),
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
  wired_moqt_on_session(hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      hub, SESS_B, ctrl_b, wired_span_of(sub_audio, sub_audio_n), 0);
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
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0 /* fin */);

  CHECK(moqtrun_test_count_kind(5) == 1); /* opened, not send_uni */
  CHECK(moqtrun_test_count_kind(4) == 0);
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->fin == 0);
  u64 relay_stream_id = opened->stream_id;

  u8         payload1 = 9;
  wired_span p1       = wired_span_of(&payload1, 1);
  u8         second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        second_off = 0;
  moqdata_obj_put(wired_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(second, second_off), 0 /* fin */);

  CHECK(moqtrun_test_count_kind(5) == 0); /* no second stream opened */
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* appended = moqtrun_test_last_kind(3);
  CHECK(appended->stream_id == relay_stream_id);
  CHECK(appended->fin == 0);
}

/* Establishes SESS_A publishing chat+audio+screen and SESS_B subscribed to
 * screen, returning ctrl_a -- the screen twin of
 * moqtrun_test_setup_audio_relay, proving relays[] is set up identically
 * for a third, differently-named track. */
static u64 moqtrun_test_setup_screen_relay(wired_moqt_hub* hub) {
  u64 ctrl_a = moqtrun_test_publish_alice(hub);
  moqtrun_test_publish_alice_audio(hub, ctrl_a);
  moqtrun_test_publish_alice_screen(hub, ctrl_a);
  wired_moqt_on_session(hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_screen[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_screen_n = moqtrun_test_subscribe_screen_msg(sub_screen);
  wired_moqt_on_stream_data(
      hub, SESS_B, ctrl_b, wired_span_of(sub_screen, sub_screen_n), 0);
  return ctrl_a;
}

/* Screen's own twin of test_moqtrun_audio_first_object_opens_then_appends:
 * the first Object relayed on the SCREEN track opens the subscriber's
 * relay stream (open_uni_stream, no FIN) and a second Object on the same
 * publisher stream_id appends to that same stream_id (stream_send, still
 * no FIN) -- proving a screen-share relay behaves exactly like the
 * long-lived audio relay, and that its relays[] slot (tracks[2], distinct
 * from audio's tracks[1]) is genuinely independent: this track was never
 * touched by the audio setup/append calls above. */
static void test_moqtrun_screen_first_object_opens_then_appends(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_screen_relay(&hub);

  moqtrun_test_reset();
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x03, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0 /* fin */);

  CHECK(moqtrun_test_count_kind(5) == 1); /* opened, not send_uni */
  CHECK(moqtrun_test_count_kind(4) == 0);
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->fin == 0);
  u64 relay_stream_id = opened->stream_id;

  u8         payload1 = 9;
  wired_span p1       = wired_span_of(&payload1, 1);
  u8         second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        second_off = 0;
  moqdata_obj_put(wired_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(second, second_off), 0 /* fin */);

  CHECK(moqtrun_test_count_kind(5) == 0); /* no second stream opened */
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* appended = moqtrun_test_last_kind(3);
  CHECK(appended->stream_id == relay_stream_id);
  CHECK(appended->fin == 0);
}

/* A publisher that drops WITHOUT FINing its relay stream (a crash, or any
 * disconnect mid-share) leaves each subscriber's relay stream open on the
 * transport: the hub's own bookkeeping forgets it (moqtrun_drop_peer_subs),
 * but nothing tells the SUBSCRIBER's session that stream is dead, so their
 * WebTransport stack keeps counting it against their own peer-granted
 * uni-stream limit forever. When the publisher reconnects and re-shares,
 * the re-PUBLISH must reset every such orphaned stream (io.stream_reset)
 * before opening a fresh one -- otherwise every drop+reshare cycle burns
 * one uni-stream slot on every subscriber permanently, until their whole
 * connection eventually runs out and nothing (chat included) can open a
 * new stream to them at all. */
static void test_moqtrun_republish_resets_orphaned_relay_stream(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_screen_relay(&hub);

  moqtrun_test_reset();
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x03, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0 /* fin */);
  u64 orphan_stream_id = moqtrun_test_last_kind(5)->stream_id;

  wired_moqt_on_session_close(&hub, SESS_A); /* sharer drops mid-share */

  moqtrun_test_reset();
  u64 ctrl_a2 = moqtrun_test_publish_alice(&hub); /* rejoin + re-PUBLISH chat */
  moqtrun_test_publish_alice_audio(&hub, ctrl_a2);
  moqtrun_test_publish_alice_screen(&hub, ctrl_a2);

  CHECK(moqtrun_test_count_kind(7) == 1); /* the orphan is reset exactly once */
  CHECK(moqtrun_test_last_kind(7)->s == SESS_B);
  CHECK(moqtrun_test_last_kind(7)->stream_id == orphan_stream_id);
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
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0 /* fin */);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 1 /* fin: close */);

  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->fin == 1);
  CHECK(moqtrun_test_count_kind(5) == 0);

  /* A fresh publisher stream_id after the close opens a fresh relay
   * stream, not an append to the now-closed one. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1001, wired_span_of(first, first_n), 0 /* fin */);
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
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1 /* chat's publisher stream is always one-shot, FIN'd */);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1000,
      wired_span_of(
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
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  u64 relay_stream_id = moqtrun_test_last_kind(5)->stream_id;

  u8         payload1 = 9;
  wired_span p1       = wired_span_of(&payload1, 1);
  u8         second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        second_off = 0;
  moqdata_obj_put(wired_mspan_of(second, sizeof second), &second_off, 1, p1);

  g_stream_send_reject_n = 1; /* the next stream_send call is refused */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(second, second_off), 0);
  CHECK(
      moqtrun_test_last_kind(3)->stream_id == relay_stream_id); /* attempted */
  CHECK(hub.stat_relay_drop == 1); /* the dropped round is counted */

  /* a 3rd Object still appends to the SAME stream, unaffected by the
   * earlier rejection. */
  u8         payload2 = 10;
  wired_span p2       = wired_span_of(&payload2, 1);
  u8         third[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        third_off = 0;
  moqdata_obj_put(wired_mspan_of(third, sizeof third), &third_off, 1, p2);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(third, third_off), 0);
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->stream_id == relay_stream_id);
  CHECK(moqtrun_test_count_kind(5) == 0); /* still no re-open */
  CHECK(hub.stat_relay_drop == 1 && hub.stat_relay_sent == 1);
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

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_b[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_b_n = moqtrun_test_subscribe_audio_msg(sub_b);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(sub_b, sub_b_n), 0);

  wired_moqt_on_session(&hub, SESS_C, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_c[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_c_n = moqtrun_test_subscribe_audio_msg(sub_c);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, wired_span_of(sub_c, sub_c_n), 0);

  moqtrun_test_reset();
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);

  CHECK(moqtrun_test_count_kind(5) == 2); /* one open per subscriber */
  u64 sid_b = 0, sid_c = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 5) continue;
    if (g_calls[i].s == SESS_B) sid_b = g_calls[i].stream_id;
    if (g_calls[i].s == SESS_C) sid_c = g_calls[i].stream_id;
  }
  CHECK(sid_b != 0 && sid_c != 0 && sid_b != sid_c);

  u8         payload1 = 9;
  wired_span p1       = wired_span_of(&payload1, 1);
  u8         second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        second_off = 0;
  moqdata_obj_put(wired_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(second, second_off), 0);
  CHECK(moqtrun_test_count_kind(3) == 2); /* each subscriber's own append */
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 3) continue;
    if (g_calls[i].s == SESS_B) CHECK(g_calls[i].stream_id == sid_b);
    if (g_calls[i].s == SESS_C) CHECK(g_calls[i].stream_id == sid_c);
  }
}

/* A refused one-shot relay open (send_uni returning failure: the
 * receiver's send slots or stream limit exhausted) loses that ONE
 * subscriber's copy of the message -- it must be counted in
 * stat_open_drop (never silent), while the other subscriber's copy still
 * goes out. */
static void test_moqtrun_send_uni_failure_counts_open_drop(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  wired_moqt_on_session(&hub, SESS_C, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  g_send_uni_fail_n = 1; /* the FIRST subscriber's open is refused */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1 /* one-shot: data + FIN together */);
  CHECK(moqtrun_test_count_kind(4) == 2); /* both sends attempted */
  CHECK(hub.stat_open_drop == 1);         /* the refused one is counted */
}

/* A fresh keep-open publisher stream arriving with every relay entry of
 * its track busy is not relayed at all -- that whole stream's payload is
 * lost for EVERY subscriber, so it must be counted (stat_relay_full),
 * never silent. */
static void test_moqtrun_relay_table_full_counts(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  for (usz i = 0; i <= WIRED_MOQTRUN_MAX_RELAYS; i++)
    wired_moqt_on_stream_data(
        &hub, SESS_A, 999 + 4 * (u64)i,
        wired_span_of(
            g_moqt_data_subgroup_stream_basic,
            G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
        0 /* keep-open: each claims a relay entry */);
  CHECK(moqtrun_test_count_kind(5) == WIRED_MOQTRUN_MAX_RELAYS);
  CHECK(hub.stat_relay_full == 1); /* the one past the table is counted */
}

/* ===================== 8b. busy-streak shed (stale backlog -> reset)
 * ===================== */

/* One header-less Object round (payload byte v) on publisher stream
 * pub_sid -- an append to an already-started relay. */
static void moqtrun_test_send_audio_round(
    wired_moqt_hub* hub, u64 pub_sid, u8 v) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        off = 0;
  wired_span p   = wired_span_of(&v, 1);
  moqdata_obj_put(wired_mspan_of(buf, sizeof buf), &off, 1, p);
  wired_moqt_on_stream_data(hub, SESS_A, pub_sid, wired_span_of(buf, off), 0);
}

/* Starts the audio relay (SESS_A publishing, SESS_B subscribed, first
 * Object delivered) and returns the subscriber-side relay stream id. */
static u64 moqtrun_test_start_busy_fixture(wired_moqt_hub* hub) {
  moqtrun_test_reset();
  wired_moqt_init(hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(hub);
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  return moqtrun_test_last_kind(5)->stream_id;
}

/* Sustained busy sheds the stream at the threshold, not before: K-1
 * consecutive refused rounds leave it bound (a transient burst must not
 * churn streams), the K-th refusal resets it exactly once (stream_reset on
 * the relay stream's own id, counted in stat_relay_reset), and the NEXT
 * round re-opens a fresh stream carrying the saved SUBGROUP_HEADER alone
 * -- the same late-open path a late subscriber takes, so the client's
 * decoder sees a well-formed stream head at the newest frame. */
static void test_moqtrun_busy_streak_sheds_after_threshold(void) {
  wired_moqt_hub hub;
  u64            relay_stream_id   = moqtrun_test_start_busy_fixture(&hub);
  const wired_moqtrun_relay* relay = &hub.peers[0].tracks[1].relays[0];

  moqtrun_test_reset();
  g_stream_send_reject_n = WIRED_MOQTRUN_RESET_AFTER_BUSY - 1;
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY - 1; v++)
    moqtrun_test_send_audio_round(&hub, 999, v);
  CHECK(moqtrun_test_count_kind(7) == 0); /* K-1: still bound */
  CHECK(hub.stat_relay_reset == 0);

  moqtrun_test_reset();
  g_stream_send_reject_n = 1;
  moqtrun_test_send_audio_round(&hub, 999, 9); /* K-th refusal */
  CHECK(moqtrun_test_count_kind(7) == 1);
  CHECK(moqtrun_test_last_kind(7)->stream_id == relay_stream_id);
  CHECK(moqtrun_test_last_kind(7)->s == SESS_B);
  CHECK(hub.stat_relay_reset == 1);

  /* Next round: late-open with the saved header, no append to the dead
   * stream. */
  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 10);
  CHECK(moqtrun_test_count_kind(5) == 1);
  CHECK(moqtrun_test_count_kind(3) == 0);
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->payload_len == relay->hdr_len);
  for (usz i = 0; i < opened->payload_len; i++)
    CHECK(opened->payload[i] == relay->hdr[i]);

  /* And the round after that appends normally to the fresh stream. */
  u64 fresh_id = opened->stream_id;
  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 11);
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->stream_id == fresh_id);
}

/* An accepted round in the middle of a busy run zeroes the streak: two
 * separated sub-threshold bursts never add up to a shed. */
static void test_moqtrun_busy_streak_success_resets(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_busy_fixture(&hub);

  moqtrun_test_reset();
  g_stream_send_reject_n = WIRED_MOQTRUN_RESET_AFTER_BUSY - 1;
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY - 1; v++)
    moqtrun_test_send_audio_round(&hub, 999, v);
  moqtrun_test_send_audio_round(&hub, 999, 20); /* accepted: streak -> 0 */
  g_stream_send_reject_n = WIRED_MOQTRUN_RESET_AFTER_BUSY - 1;
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY - 1; v++)
    moqtrun_test_send_audio_round(&hub, 999, (u8)(30 + v));
  CHECK(moqtrun_test_count_kind(7) == 0);
  CHECK(hub.stat_relay_reset == 0);
}

/* After a shed, the publisher's own bare FIN must NOT be forwarded to the
 * abandoned stream id: the subscriber slot is unbound, and a FIN-only
 * round never late-opens a stream just to close it. */
static void test_moqtrun_shed_stream_skips_publisher_fin(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_busy_fixture(&hub);

  moqtrun_test_reset();
  g_stream_send_reject_n = WIRED_MOQTRUN_RESET_AFTER_BUSY;
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY; v++)
    moqtrun_test_send_audio_round(&hub, 999, v);
  CHECK(moqtrun_test_count_kind(7) == 1); /* shed happened */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(0, 0), 1);
  CHECK(moqtrun_test_count_kind(6) == 0); /* no stream_fin on the dead id */
  CHECK(moqtrun_test_count_kind(3) == 0);
}

/* The streak is per subscriber: starving ONE subscriber's session sheds
 * only that subscriber's stream -- the healthy peer's stream keeps
 * receiving every round untouched. */
static void test_moqtrun_busy_shed_isolated_per_subscriber(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_b[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_b_n = moqtrun_test_subscribe_audio_msg(sub_b);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(sub_b, sub_b_n), 0);
  wired_moqt_on_session(&hub, SESS_C, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_c[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_c_n = moqtrun_test_subscribe_audio_msg(sub_c);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, wired_span_of(sub_c, sub_c_n), 0);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_B; /* starve B only */
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY; v++)
    moqtrun_test_send_audio_round(&hub, 999, v);
  CHECK(moqtrun_test_count_kind(7) == 1);
  CHECK(moqtrun_test_last_kind(7)->s == SESS_B);
  CHECK(hub.stat_relay_reset == 1);
  /* C received every round; only B's sends were refused. */
  usz c_sends = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 3 && g_calls[i].s == SESS_C) c_sends++;
  CHECK(c_sends == WIRED_MOQTRUN_RESET_AFTER_BUSY);
}

/* io.stream_reset returning 0 (the SDK's reset latch full this step) keeps
 * the stream bound and retries the shed on the NEXT busy round -- and once
 * the reset is finally accepted, the shed completes (fresh late-open
 * afterward). The refusal never half-applies. */
static void test_moqtrun_shed_refused_retries_next_round(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_busy_fixture(&hub);

  moqtrun_test_reset();
  g_stream_reset_ret     = 0; /* SDK refuses the reset */
  g_stream_send_reject_n = WIRED_MOQTRUN_RESET_AFTER_BUSY + 1;
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY; v++)
    moqtrun_test_send_audio_round(&hub, 999, v);
  CHECK(moqtrun_test_count_kind(7) == 1); /* attempted, refused */
  CHECK(hub.stat_relay_reset == 0);
  moqtrun_test_send_audio_round(&hub, 999, 20); /* still busy: retried */
  CHECK(moqtrun_test_count_kind(7) == 2);
  CHECK(hub.stat_relay_reset == 0);

  g_stream_reset_ret     = 1; /* latch drained: reset now accepted */
  g_stream_send_reject_n = 1;
  moqtrun_test_send_audio_round(&hub, 999, 21);
  CHECK(moqtrun_test_count_kind(7) == 3);
  CHECK(hub.stat_relay_reset == 1);

  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 22);
  CHECK(moqtrun_test_count_kind(5) == 1); /* fresh late-open */
}

/* A re-PUBLISH (rejoin) clears every relay -- and with them any
 * accumulated busy streak: the fresh incarnation's first refused round
 * starts counting from zero, not from the dead relay's leftovers. */
static void test_moqtrun_republish_clears_busy_streak(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_b[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_b_n = moqtrun_test_subscribe_audio_msg(sub_b);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(sub_b, sub_b_n), 0);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);

  moqtrun_test_reset();
  g_stream_send_reject_n = WIRED_MOQTRUN_RESET_AFTER_BUSY - 1;
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY - 1; v++)
    moqtrun_test_send_audio_round(&hub, 999, v); /* streak at K-1 */

  moqtrun_test_publish_alice_audio(&hub, ctrl_a); /* rejoin: relays clear */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1001, wired_span_of(first, first_n), 0);

  moqtrun_test_reset();
  g_stream_send_reject_n = 1;
  moqtrun_test_send_audio_round(&hub, 1001, 20);
  CHECK(moqtrun_test_count_kind(7) == 0); /* fresh streak: 1 of K, no shed */
  CHECK(hub.stat_relay_reset == 0);
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
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0 /* data, no fin yet */);

  CHECK(moqtrun_test_count_kind(5) == 1); /* opened, held open */
  CHECK(moqtrun_test_count_kind(4) == 0); /* not yet a one-shot send_uni */
  u64 relay_stream_id = moqtrun_test_last_kind(5)->stream_id;

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(0, 0), 1 /* bare FIN, no bytes */);

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
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  u64 relay_stream_id = moqtrun_test_last_kind(5)->stream_id;

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(0, 0), 1);

  CHECK(moqtrun_test_count_kind(6) == 1);
  CHECK(moqtrun_test_last_kind(6)->stream_id == relay_stream_id);
  CHECK(moqtrun_test_count_kind(3) == 0);

  /* The next Object (fresh publisher stream_id) opens a new relay stream,
   * confirming the closed one was actually unbound. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1001, wired_span_of(first, first_n), 0);
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
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  moqtrun_test_reset();
  /* msg1 data (fin=0, publisher stream 999) -> opens relay stream A. */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
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
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      0);
  CHECK(moqtrun_test_count_kind(5) == 2);
  CHECK(moqtrun_test_count_kind(3) == 0); /* no append onto A */
  u64 relay_b = moqtrun_test_last_kind(5)->stream_id;
  CHECK(relay_b != relay_a);

  /* msg1's late bare FIN (999) still closes A -- not B, not nothing. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(0, 0), 1);
  CHECK(moqtrun_test_count_kind(6) == 1);
  CHECK(moqtrun_test_last_kind(6)->stream_id == relay_a);

  /* msg2's bare FIN (1003) closes B. */
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 1003, wired_span_of(0, 0), 1);
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
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  CHECK(moqtrun_test_count_kind(5) == 0);

  /* Now SESS_B subscribes to the audio track. */
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b, wired_span_of(sub_audio, sub_audio_n), 0);

  /* Next frame (bare Object, same publisher stream): late-opens B's relay
   * stream carrying the saved SUBGROUP_HEADER alone. The header here is
   * the golden stream's first 2 bytes (Type 0x70 rewritten alias 0x02 --
   * Group ID rides mode 0b00's explicit field within those bytes for this
   * golden vector's small values). */
  u8         payload1 = 9;
  wired_span p1       = wired_span_of(&payload1, 1);
  u8         second[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        second_off = 0;
  moqdata_obj_put(wired_mspan_of(second, sizeof second), &second_off, 1, p1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(second, second_off), 0);
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
      &hub, SESS_A, 999, wired_span_of(second, second_off), 0);
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
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);

  /* One 5-byte-payload Object, split mid-payload across two deliveries. */
  u8  payload[5] = {1, 2, 3, 4, 5};
  u8  obj[MOQTRUN_TEST_MAX_PAYLOAD];
  usz obj_n = 0;
  moqdata_obj_put(
      wired_mspan_of(obj, sizeof obj), &obj_n, 1, wired_span_of(payload, 5));
  usz cut = obj_n - 3; /* tear inside the payload */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(obj, cut), 0);
  CHECK(moqtrun_test_count_kind(3) == 0); /* torn: nothing forwarded */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(obj + cut, obj_n - cut), 0);
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
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);

  u8  pa[3] = {0xA, 0xA, 0xA};
  u8  pb[4] = {0xB, 0xB, 0xB, 0xB};
  u8  pc[5] = {0xC, 0xC, 0xC, 0xC, 0xC};
  u8  abc[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = 0;
  moqdata_obj_put(wired_mspan_of(abc, sizeof abc), &n, 1, wired_span_of(pa, 3));
  usz a_end = n;
  moqdata_obj_put(wired_mspan_of(abc, sizeof abc), &n, 1, wired_span_of(pb, 4));
  usz b_end = n;
  moqdata_obj_put(wired_mspan_of(abc, sizeof abc), &n, 1, wired_span_of(pc, 5));
  usz cut1 = a_end - 2; /* first delivery tears inside A */
  usz cut2 = b_end + 3; /* second delivery ends inside C */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(abc, cut1), 0);
  CHECK(moqtrun_test_count_kind(3) == 0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(abc + cut1, cut2 - cut1), 0);
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->payload_len == b_end); /* A+B whole, C's head held back */
  for (usz i = 0; i < b_end; i++) CHECK(sent->payload[i] == abc[i]);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(abc + cut2, n - cut2), 0);
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
  moqdata_obj_put(
      wired_mspan_of(wire, sizeof wire), &n, 1, wired_span_of(p2, 4));
  usz cut = whole_end + 2; /* tear inside the 2nd Object */

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(wire, cut), 0);
  CHECK(moqtrun_test_count_kind(5) == 1);
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->payload_len == whole_end); /* torn tail not in the open */
  for (usz i = 0; i < whole_end; i++) CHECK(opened->payload[i] == wire[i]);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(wire + cut, n - cut), 0);
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->payload_len == n - whole_end); /* the completed 2nd Object */
  for (usz i = 0; i < n - whole_end; i++)
    CHECK(sent->payload[i] == wire[whole_end + i]);
}

/* The OPENING delivery can even be torn before its FIRST Object completes
 * (a 200KB attachment's first slice easily ends mid-Object): with no FIN,
 * the header alone is worth accepting -- the relay opens each subscriber's
 * stream carrying just the header, holds the torn head as the first
 * fragment, and the next delivery completes it. Dropping the stream here
 * would orphan every later (header-less) delivery on it. */
static void test_moqtrun_fresh_torn_first_object_accepted(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8  wire[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n        = moqtrun_test_subgroup_with_alias(0x02, wire); /* hdr + obj0 */
  usz obj0_end = n;
  usz hdr_end  = 0;
  moqdata_subhdr hdr;
  CHECK(
      moqdata_subhdr_take(wired_span_of(wire, n), &hdr_end, &hdr) ==
      MOQDATA_OK);
  u8 p2[4] = {9, 9, 9, 9};
  moqdata_obj_put(
      wired_mspan_of(wire, sizeof wire), &n, 1, wired_span_of(p2, 4));
  usz cut = (hdr_end + obj0_end) / 2; /* tear inside Object 0 */
  CHECK(hdr_end < cut && cut < obj0_end);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(wire, cut), 0);
  CHECK(moqtrun_test_count_kind(5) == 1); /* opened despite 0 whole Objects */
  const moqtrun_test_call* opened = moqtrun_test_last_kind(5);
  CHECK(opened->payload_len == hdr_end); /* header alone, torn head held */
  for (usz i = 0; i < hdr_end; i++) CHECK(opened->payload[i] == wire[i]);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(wire + cut, n - cut), 0);
  CHECK(moqtrun_test_count_kind(5) == 0); /* same stream, no reopen */
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->payload_len == n - hdr_end); /* Object 0 + Object 1, in order */
  for (usz i = 0; i < n - hdr_end; i++)
    CHECK(sent->payload[i] == wire[hdr_end + i]);
}

/* A one-shot delivery (FIN with the data) whose Objects are ALL torn has
 * no continuation coming: header + zero complete Objects relays nothing --
 * no one-shot send, no stream opened. */
static void test_moqtrun_fresh_oneshot_no_object_discarded(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_setup_audio_relay(&hub);

  u8             wire[MOQTRUN_TEST_MAX_PAYLOAD];
  usz            n       = moqtrun_test_subgroup_with_alias(0x02, wire);
  usz            hdr_end = 0;
  moqdata_subhdr hdr;
  CHECK(
      moqdata_subhdr_take(wired_span_of(wire, n), &hdr_end, &hdr) ==
      MOQDATA_OK);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(wire, hdr_end + 1), 1 /* fin */);
  CHECK(g_n_calls == 0); /* nothing complete, nothing sent */
}

/* An undeliverable tail larger than one whole relayable Object is dropped
 * (torn frame for that stream) and counted on the hub; an in-bounds tail is
 * saved without touching the counter. */
static void test_moqtrun_frag_overflow_counted(void) {
  static wired_moqt_hub hub;
  static u8             tail[WIRED_MOQTRUN_RELAY_FRAG_MAX + 1];
  wired_moqtrun_relay   relay = {0};
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_relay_save_frag(&hub, &relay, tail, sizeof tail);
  CHECK(relay.frag_len == 0 && hub.stat_frag_drop == 1);
  moqtrun_relay_save_frag(&hub, &relay, tail, 3);
  CHECK(relay.frag_len == 3 && hub.stat_frag_drop == 1);
}

/* ===================== session teardown ===================== */

/* A closed session's peer slot is freed: the SAME wt pointer re-registers
 * as a fresh peer and receives a fresh SETUP. The SDK reuses connection-
 * slot memory (a reconnecting client often gets a pointer-identical
 * session), so without the free, on_session's duplicate guard mistook the
 * reconnect for the dead peer and never sent SETUP -- the client stayed
 * mute until the process restarted. */
static void test_moqtrun_close_frees_peer_for_reregistration(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  CHECK(moqtrun_test_count_kind(1) == 1);

  wired_moqt_on_session_close(&hub, SESS_A);
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));

  CHECK(moqtrun_test_count_kind(1) == 2); /* fresh SETUP for the reconnect */
}

/* Closing a subscriber deactivates its entries on every other peer's
 * tracks: a later Object on the publisher's track is not relayed to the
 * dead session. */
static void test_moqtrun_close_drops_subscriptions(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session_close(&hub, SESS_B);
  moqtrun_test_reset(); /* only observe the relay's own calls */
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1);

  CHECK(moqtrun_test_count_kind(4) == 0); /* nothing relayed to the dead B */
  CHECK(hub.stat_relay_sent == 0);
}

/* Registers session s and returns its control stream id. */
static u64 moqtrun_test_join(wired_moqt_hub* hub, wired_wt_session* s) {
  wired_moqt_on_session(hub, s, wired_span_of(0, 0), wired_span_of(0, 0));
  return moqtrun_test_last_kind(1)->stream_id;
}

/* Publisher s PUBLISHes a track named name (Track Alias alias) on ctrl. */
static void moqtrun_test_publish_named(
    wired_moqt_hub*   hub,
    wired_wt_session* s,
    u64               ctrl,
    const u8*         name,
    usz               name_len,
    u8                alias) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_rename_track(
      g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN, name, name_len,
      buf);
  buf[n - 2] = alias;
  wired_moqt_on_stream_data(hub, s, ctrl, wired_span_of(buf, n), 0);
}

/* Subscriber s SUBSCRIBEs to the track named name on ctrl. */
static void moqtrun_test_subscribe_named(
    wired_moqt_hub*   hub,
    wired_wt_session* s,
    u64               ctrl,
    const u8*         name,
    usz               name_len) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_rename_track(
      g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN, name,
      name_len, buf);
  wired_moqt_on_stream_data(hub, s, ctrl, wired_span_of(buf, n), 0);
}

/* Publisher A's chat Object (the golden SUBGROUP stream, alias 1) arrives
 * on a fresh data stream; returns how many subscriber streams it opened. */
static usz moqtrun_test_relay_alice_chat(wired_moqt_hub* hub) {
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      hub, SESS_A, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1);
  return moqtrun_test_count_kind(4);
}

/* A subscriber re-sending SUBSCRIBE for a track it already holds (the
 * client resends every second until a chunk arrives, and an idle track
 * never sends one) is answered SUBSCRIBE_OK with its existing slot, not a
 * fresh one: past the table's capacity the resends would otherwise turn
 * into DOES_NOT_EXIST for everyone, and a later Object would be relayed to
 * the same peer once per slot it had piled up. */
static void test_moqtrun_duplicate_subscribe_reuses_slot(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  u64 ctrl_b = moqtrun_test_join(&hub, SESS_B);

  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS + 1; i++) {
    moqtrun_test_reset();
    wired_moqt_on_stream_data(
        &hub, SESS_B, ctrl_b,
        wired_span_of(
            g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
        0);
    CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  }

  CHECK(moqtrun_test_relay_alice_chat(&hub) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* The publisher drops and rejoins, re-PUBLISHing the same name: its
 * subscriber, whose client still believes the subscription stands, is
 * re-attached and receives the rejoined publisher's next Object. */
static void test_moqtrun_republish_reattaches_subscriber(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  u64 ctrl_b = moqtrun_test_join(&hub, SESS_B);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session_close(&hub, SESS_A);
  moqtrun_test_publish_alice(&hub); /* rejoin + re-PUBLISH "alice" */

  CHECK(moqtrun_test_relay_alice_chat(&hub) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* Each of three other participants publishes chat+audio+screen (nine
 * names); B subscribes to all nine, oldest first. The first publisher then
 * drops and rejoins: its chat Object must still reach B -- the name B
 * subscribed to first has to survive eight newer ones. */
static void test_moqtrun_reattach_survives_nine_subscribed_names(void) {
  static const u8 names[9][12] = {
      {'a', 'l', 'i', 'c', 'e'},
      {'a', 'l', 'i', 'c', 'e', '/', 'a', 'u', 'd', 'i', 'o'},
      {'a', 'l', 'i', 'c', 'e', '/', 's', 'c', 'r', 'e', 'e', 'n'},
      {'c', 'a', 'r', 'o', 'l'},
      {'c', 'a', 'r', 'o', 'l', '/', 'a', 'u', 'd', 'i', 'o'},
      {'c', 'a', 'r', 'o', 'l', '/', 's', 'c', 'r', 'e', 'e', 'n'},
      {'d', 'a', 'v', 'e'},
      {'d', 'a', 'v', 'e', '/', 'a', 'u', 'd', 'i', 'o'},
      {'d', 'a', 'v', 'e', '/', 's', 'c', 'r', 'e', 'e', 'n'},
  };
  static const usz lens[9] = {5, 11, 12, 5, 11, 12, 4, 10, 11};
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_wt_session* const pubs[3] = {SESS_A, SESS_C, SESS_D};
  for (usz p = 0; p < 3; p++) {
    u64 ctrl = moqtrun_test_join(&hub, pubs[p]);
    for (usz t = 0; t < 3; t++)
      moqtrun_test_publish_named(
          &hub, pubs[p], ctrl, names[p * 3 + t], lens[p * 3 + t], (u8)(t + 1));
  }
  u64 ctrl_b = moqtrun_test_join(&hub, SESS_B);
  for (usz i = 0; i < 9; i++)
    moqtrun_test_subscribe_named(&hub, SESS_B, ctrl_b, names[i], lens[i]);

  wired_moqt_on_session_close(&hub, SESS_A);
  moqtrun_test_reset();
  moqtrun_test_publish_alice(&hub); /* rejoin + re-PUBLISH "alice" */

  CHECK(moqtrun_test_relay_alice_chat(&hub) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* A subscriber that drops and re-registers (the SDK often hands the same
 * session pointer back) starts with no remembered names: the publisher's
 * later re-PUBLISH must not re-attach it to a track it never re-SUBSCRIBEd
 * to on its new session. */
static void test_moqtrun_reconnected_subscriber_is_not_reattached(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  u64 ctrl_b = moqtrun_test_join(&hub, SESS_B);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session_close(&hub, SESS_B);
  moqtrun_test_join(&hub, SESS_B); /* same pointer, fresh session */
  wired_moqt_on_session_close(&hub, SESS_A);
  moqtrun_test_publish_alice(&hub);

  CHECK(moqtrun_test_relay_alice_chat(&hub) == 0);
}

/* A peer that had subscribed to a name and then PUBLISHes that name itself
 * (the original publisher gone) is not attached as its own subscriber. */
static void test_moqtrun_publisher_is_not_reattached_to_own_track(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  u64 ctrl_b = moqtrun_test_join(&hub, SESS_B);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);

  wired_moqt_on_session_close(&hub, SESS_A);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN), 0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_B, 999,
      wired_span_of(
          g_moqt_data_subgroup_stream_basic,
          G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN),
      1);
  CHECK(moqtrun_test_count_kind(4) == 0);
}

/* A SUBSCRIBE refused with DOES_NOT_EXIST (nothing PUBLISHed yet) is not
 * remembered: when the name is PUBLISHed later, the peer -- which never
 * received SUBSCRIBE_OK -- is not silently attached. */
static void test_moqtrun_refused_subscribe_is_not_remembered(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_b = moqtrun_test_join(&hub, SESS_B);
  wired_moqt_on_stream_data(
      &hub, SESS_B, ctrl_b,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);

  moqtrun_test_publish_alice(&hub);

  CHECK(moqtrun_test_relay_alice_chat(&hub) == 0);
}

/* Closing a session the hub never registered (or one already closed) is a
 * no-op that leaves live peers untouched. */
static void test_moqtrun_close_unknown_session_noop(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));

  wired_moqt_on_session_close(&hub, SESS_B); /* never registered */
  wired_moqt_on_session_close(&hub, SESS_A);
  wired_moqt_on_session_close(&hub, SESS_A); /* already closed */

  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  CHECK(moqtrun_test_count_kind(1) == 2); /* A's SETUP + B's SETUP */
}

/* Register/close churn far past the 32-slot peer table: every reconnect
 * still gets its SETUP (a leaked slot per disconnect used to exhaust the
 * table and silently refuse everyone after). */
static void test_moqtrun_close_reregister_churn(void) {
  wired_moqt_hub hub; /* one hub across the churn, reset only the recorder */
  moqtrun_test_reset();
  wired_moqt_init(&hub, moqtrun_test_io());
  for (usz i = 0; i < 2 * WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    moqtrun_test_reset();
    wired_moqt_on_session(
        &hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
    CHECK(moqtrun_test_count_kind(1) == 1);
    wired_moqt_on_session_close(&hub, SESS_A);
  }
}

/* ===================== 12. hub-owned blob track ===================== */

static const u8 MOVIE_NAME[5] = {'m', 'o', 'v', 'i', 'e'};

/* SUBSCRIBE golden vector with its 5-byte Track Name ("alice", offset 17)
 * replaced by "movie" -- same length, so no Length backpatch. */
static usz moqtrun_test_subscribe_movie_msg(u8* buf) {
  bytes_memcpy(buf, g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN);
  bytes_memcpy(buf + 17, MOVIE_NAME, 5);
  return G_MOQT_CTL_SUBSCRIBE_BASIC_LEN;
}

static u8 g_test_blob[256];
static u8 g_test_wire[MOQDATA_BLOB_WIRE_CAP(sizeof g_test_blob)];

/* Publishes a small (recorder-sized) blob and returns its framed length
 * (the framing itself is moqdata_blob_build's, pinned in moqdata_test). */
static usz moqtrun_test_publish_small_blob(wired_moqt_hub* hub, usz n) {
  for (usz i = 0; i < n; i++) g_test_blob[i] = (u8)(i * 7 + 3);
  return wired_moqt_publish_blob(
      hub, wired_span_of(MOVIE_NAME, 5), 8, wired_span_of(g_test_blob, n),
      wired_mspan_of(g_test_wire, sizeof g_test_wire));
}

/* Drives peer s through a SUBSCRIBE for "movie" on its control stream
 * (wired_moqt_on_session is idempotent, so calling this twice for one
 * session is a re-SUBSCRIBE). */
static void moqtrun_test_subscribe_movie(
    wired_moqt_hub* hub, wired_wt_session* s) {
  wired_moqt_on_session(hub, s, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl = moqtrun_test_last_kind(1)->stream_id;
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_subscribe_movie_msg(buf);
  wired_moqt_on_stream_data(hub, s, ctrl, wired_span_of(buf, n), 0);
}

/* Type of the last control reply (0 when none); *body receives its body. */
static u64 moqtrun_test_last_reply(wired_span* body) {
  const moqtrun_test_call* c = moqtrun_test_last_kind(3);
  if (!c) return 0;
  usz off  = 0;
  u64 type = 0;
  if (moqctl_peek_type(
          wired_span_of(c->payload, c->payload_len), &off, &type, body) !=
      MOQCTL_OK)
    return 0;
  return type;
}

static u64 moqtrun_test_last_reply_type(void) {
  wired_span body;
  return moqtrun_test_last_reply(&body);
}

/* An empty blob publishes nothing -- SUBSCRIBE "movie" stays
 * DOES_NOT_EXIST, no stream opened. */
static void test_moqtrun_blob_empty_not_published(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  CHECK(moqtrun_test_publish_small_blob(&hub, 0) == 0);

  moqtrun_test_subscribe_movie(&hub, SESS_A);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
  CHECK(moqtrun_test_count_kind(4) == 0);
}

/* A wire buffer too small for the framing returns 0 and leaves the hub
 * without a blob track. */
static void test_moqtrun_blob_wire_too_small(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  CHECK(
      wired_moqt_publish_blob(
          &hub, wired_span_of(MOVIE_NAME, 5), 8,
          wired_span_of(g_test_blob, 100),
          wired_mspan_of(g_test_wire, 100)) == 0);

  moqtrun_test_subscribe_movie(&hub, SESS_A);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
  CHECK(moqtrun_test_count_kind(4) == 0);
}

/* SUBSCRIBE "movie" gets SUBSCRIBE_OK carrying the blob's own alias (the
 * one its framed header has) and exactly one send_uni to that session
 * carrying the framed bytes verbatim. */
static void test_moqtrun_blob_subscribe_sends_once(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  usz wl = moqtrun_test_publish_small_blob(&hub, 100);
  CHECK(wl > 100 && wl < MOQTRUN_TEST_MAX_PAYLOAD);

  moqtrun_test_subscribe_movie(&hub, SESS_A);

  wired_span body;
  CHECK(moqtrun_test_last_reply(&body) == MOQCTL_T_SUBSCRIBE_OK);
  moqctl_subscribe_ok ok;
  usz                 body_off = 0;
  CHECK(moqctl_subscribe_ok_take(body, &body_off, &ok) == MOQCTL_OK);
  CHECK(ok.track_alias == 8);
  CHECK(moqtrun_test_count_kind(4) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(4);
  CHECK(sent->s == SESS_A);
  CHECK(sent->payload_len == wl);
  CHECK(ct_diffn(sent->payload, g_test_wire, wl) == 0);
}

/* A repeat SUBSCRIBE from the same peer is answered SUBSCRIBE_OK again but
 * does not send a second copy. */
static void test_moqtrun_blob_resubscribe_no_resend(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_small_blob(&hub, 100);

  moqtrun_test_subscribe_movie(&hub, SESS_A);
  moqtrun_test_subscribe_movie(&hub, SESS_A);

  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(4) == 1);
}

/* Two peers each get their own copy on their own session. */
static void test_moqtrun_blob_two_peers_each_get_copy(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_small_blob(&hub, 100);

  moqtrun_test_subscribe_movie(&hub, SESS_A);
  moqtrun_test_subscribe_movie(&hub, SESS_B);

  CHECK(moqtrun_test_count_kind(4) == 2);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
  usz to_a = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 4 && g_calls[i].s == SESS_A) to_a++;
  CHECK(to_a == 1);
}

/* A refused send_uni is reported as REQUEST_ERROR (no subscription
 * recorded, open drop counted) so a later re-SUBSCRIBE sends afresh. */
static void test_moqtrun_blob_send_refused_then_retry(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_small_blob(&hub, 100);

  g_send_uni_fail_n = 1;
  moqtrun_test_subscribe_movie(&hub, SESS_A);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
  CHECK(hub.stat_open_drop == 1);

  moqtrun_test_subscribe_movie(&hub, SESS_A);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(4) == 2); /* the refused try + the good one */
  CHECK(moqtrun_test_last_kind(4)->payload_len > 100);
}

/* Closing a session forgets its blob subscription, so a reconnect landing
 * in the same peer slot receives the blob again. */
static void test_moqtrun_blob_close_then_reconnect_resends(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_small_blob(&hub, 100);

  moqtrun_test_subscribe_movie(&hub, SESS_A);
  wired_moqt_on_session_close(&hub, SESS_A);
  moqtrun_test_subscribe_movie(&hub, SESS_B); /* reuses A's freed slot */

  CHECK(moqtrun_test_count_kind(4) == 2);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* The hub's blob answers a SUBSCRIBE for its name even when a peer has
 * PUBLISHed a track under the same name (hub-owned wins). */
static void test_moqtrun_blob_shadows_peer_track_of_same_name(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_small_blob(&hub, 100);
  /* Peer A PUBLISHes "movie": the golden PUBLISH's 5-byte name is also at
   * offset 17 (moqtrun_test_rename_track_to_audio's layout note). */
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_a = moqtrun_test_last_kind(1)->stream_id;
  u8  pub[MOQTRUN_TEST_MAX_PAYLOAD];
  bytes_memcpy(pub, g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN);
  bytes_memcpy(pub + 17, MOVIE_NAME, 5);
  wired_moqt_on_stream_data(
      &hub, SESS_A, ctrl_a, wired_span_of(pub, G_MOQT_CTL_PUBLISH_BASIC_LEN),
      0);

  moqtrun_test_subscribe_movie(&hub, SESS_B);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(4) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* ===================== 13. hub-owned live track ===================== */

static const u8   LIVE_NAME[5] = {'m', 'o', 'v', 'i', 'e'};
static u8         g_live_frag[3][64];
static wired_span g_live_frags[3];

/* Three distinct 40/50/60-byte fragments, cadence 2000 ms from t0=1000. */
static void moqtrun_test_publish_live(wired_moqt_hub* hub) {
  for (usz f = 0; f < 3; f++) {
    for (usz i = 0; i < 40 + 10 * f; i++) g_live_frag[f][i] = (u8)(f * 50 + i);
    g_live_frags[f] = wired_span_of(g_live_frag[f], 40 + 10 * f);
  }
  CHECK(
      wired_moqt_publish_live(
          hub, wired_span_of(LIVE_NAME, 5), 8, g_live_frags, 3, 2000, 1000) ==
      1);
}

/* Same shape as moqtrun_test_subscribe_movie (name "movie"). */
static void moqtrun_test_subscribe_live(
    wired_moqt_hub* hub, wired_wt_session* s) {
  moqtrun_test_subscribe_movie(hub, s);
}

/* Decodes a recorded send_uni2 call as SUBGROUP_HEADER + one Object;
 * returns the Group ID and copies the payload to out (n bytes). */
static u64 moqtrun_test_live_group(
    const moqtrun_test_call* c, u8* out, usz* n) {
  usz            off = 0;
  moqdata_subhdr hdr;
  CHECK(
      moqdata_subhdr_take(
          wired_span_of(c->payload, c->payload_len), &off, &hdr) == MOQDATA_OK);
  CHECK(hdr.track_alias == 8);
  moqdata_objseq seq = moqdata_objseq_of(hdr.type);
  moqdata_obj    obj;
  CHECK(
      moqdata_obj_take(
          wired_span_of(c->payload, c->payload_len), &off, &seq, &obj) ==
      MOQDATA_OK);
  CHECK(obj.object_id == 0);
  CHECK(off == c->payload_len);
  bytes_memcpy(out, obj.payload.p, obj.payload.n);
  *n = obj.payload.n;
  return hdr.group_id;
}

static void test_moqtrun_live_publish_rejects_bad_args(void) {
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  g_live_frags[0] = wired_span_of(g_live_frag[0], 4);
  CHECK(
      wired_moqt_publish_live(
          &hub, wired_span_of(LIVE_NAME, 5), 8, g_live_frags, 0, 2000, 0) == 0);
  CHECK(
      wired_moqt_publish_live(
          &hub, wired_span_of(LIVE_NAME, 5), 8, g_live_frags, 1, 0, 0) == 0);
}

/* A zero-length fragment cannot frame as a valid Object (an empty payload
 * needs the explicit Status varint the live head never carries), so the
 * whole publish is refused and the track never exists. */
static void test_moqtrun_live_empty_fragment_rejected(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  g_live_frags[0] = wired_span_of(g_live_frag[0], 4);
  g_live_frags[1] = wired_span_of(g_live_frag[1], 0); /* empty middle */
  g_live_frags[2] = wired_span_of(g_live_frag[2], 4);
  CHECK(
      wired_moqt_publish_live(
          &hub, wired_span_of(LIVE_NAME, 5), 8, g_live_frags, 3, 2000, 0) == 0);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
  CHECK(moqtrun_test_count_kind(8) == 0);
}

/* SUBSCRIBE at t=1000+2500 (Group 1): SUBSCRIBE_OK alias 8 and one
 * immediate send of Group 1 = fragment 1. */
static void test_moqtrun_live_subscribe_sends_current_group(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 3500);
  moqtrun_test_subscribe_live(&hub, SESS_A);

  wired_span body;
  CHECK(moqtrun_test_last_reply(&body) == MOQCTL_T_SUBSCRIBE_OK);
  moqctl_subscribe_ok ok;
  usz                 boff = 0;
  CHECK(moqctl_subscribe_ok_take(body, &boff, &ok) == MOQCTL_OK);
  CHECK(ok.track_alias == 8);
  CHECK(moqtrun_test_count_kind(8) == 1);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 1);
  CHECK(n == 50 && ct_diffn(got, g_live_frag[1], 50) == 0);
  CHECK(hub.stat_live_sent == 1);
}

/* Ticks inside the same Group send nothing; the tick that enters the
 * next Group sends the next fragment; fragments wrap at n_frags. */
static void test_moqtrun_live_tick_advances_groups(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A); /* Group 0 */
  wired_moqt_tick(&hub, 1500);
  wired_moqt_tick(&hub, 2999);
  CHECK(moqtrun_test_count_kind(8) == 1);
  wired_moqt_tick(&hub, 3000); /* Group 1 */
  wired_moqt_tick(&hub, 5000); /* Group 2 */
  wired_moqt_tick(&hub, 7000); /* Group 3 -> fragment 0 again */
  CHECK(moqtrun_test_count_kind(8) == 4);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 3);
  CHECK(n == 40 && ct_diffn(got, g_live_frag[0], 40) == 0);
}

/* A refused send is retried on the next tick of the SAME Group and
 * abandoned (counted) once the Group advances -- never sent late. */
static void test_moqtrun_live_refused_send_retries_then_drops(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  CHECK(moqtrun_test_count_kind(8) == 1);

  g_send_uni2_fail_n = 1;
  wired_moqt_tick(&hub, 3000); /* Group 1: refused */
  CHECK(hub.stat_live_sent == 1);
  wired_moqt_tick(&hub, 3100); /* still Group 1: retried, accepted */
  CHECK(hub.stat_live_sent == 2);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 1);

  g_send_uni2_fail_n = 1;
  wired_moqt_tick(&hub, 5000); /* Group 2: refused (attempt recorded) */
  usz after_refusal = g_n_calls;
  wired_moqt_tick(&hub, 7000); /* Group 3: Group 2 abandoned, 3 sent */
  CHECK(hub.stat_live_drop == 1);
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 3);
  /* Once the clock left Group 2, its fragment is never attempted again --
   * the scan starts after the (timely, refused) Group-2 attempt above. */
  for (usz i = after_refusal; i < g_n_calls; i++) {
    if (g_calls[i].kind != 8) continue;
    u8  p[64];
    usz pn;
    CHECK(moqtrun_test_live_group(&g_calls[i], p, &pn) != 2); /* never late */
  }
}

/* Two subscribers are independent: one refused, the other still served. */
static void test_moqtrun_live_two_subscribers_independent(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  moqtrun_test_subscribe_live(&hub, SESS_B);
  CHECK(moqtrun_test_count_kind(8) == 2);
  g_send_uni2_reject_sess = SESS_A;
  wired_moqt_tick(&hub, 3000);
  CHECK(moqtrun_test_last_kind(8)->s == SESS_B);
  usz to_b = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 8 && g_calls[i].s == SESS_B) to_b++;
  CHECK(to_b == 2);
  CHECK(hub.stat_live_sent == 3);
}

/* Repeat SUBSCRIBE: SUBSCRIBE_OK again, nothing sent. */
static void test_moqtrun_live_resubscribe_no_resend(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(8) == 1);
}

/* Close stops sends; a reconnect in the same slot starts at the current
 * Group. */
static void test_moqtrun_live_close_then_reconnect(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  wired_moqt_on_session_close(&hub, SESS_A);
  wired_moqt_tick(&hub, 3000);
  CHECK(moqtrun_test_count_kind(8) == 1);
  wired_moqt_tick(&hub, 5000);
  moqtrun_test_subscribe_live(&hub, SESS_B);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 2);
}

/* Blob and live tracks coexist and route by name. */
static void test_moqtrun_live_and_blob_coexist(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  static const u8 INIT_NAME[10] = {'m', 'o', 'v', 'i', 'e',
                                   '/', 'i', 'n', 'i', 't'};
  for (usz i = 0; i < 100; i++) g_test_blob[i] = (u8)i;
  CHECK(
      wired_moqt_publish_blob(
          &hub, wired_span_of(INIT_NAME, 10), 9,
          wired_span_of(g_test_blob, 100),
          wired_mspan_of(g_test_wire, sizeof g_test_wire)) > 0);
  wired_moqt_tick(&hub, 1000);
  /* SUBSCRIBE "movie/init": golden SUBSCRIBE with its Track Name renamed
   * (moqtrun_test_rename_track backpatches the Length for the longer
   * name). */
  wired_moqt_on_session(&hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl = moqtrun_test_last_kind(1)->stream_id;
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sn = moqtrun_test_rename_track(
      g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN, INIT_NAME, 10,
      buf);
  wired_moqt_on_stream_data(&hub, SESS_A, ctrl, wired_span_of(buf, sn), 0);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(4) == 1); /* blob: send_uni */
  moqtrun_test_subscribe_live(&hub, SESS_A);
  CHECK(moqtrun_test_count_kind(8) == 1); /* live: send_uni2 */
}

/* ===================== 9. OBJECT_DATAGRAM relay ===================== */

/* Registers s, opens its control stream, and SUBSCRIBEs it to the chat
 * track ("alice") -- shared setup for the datagram-relay tests below. */
static void moqtrun_test_subscribe_chat(
    wired_moqt_hub* hub, wired_wt_session* s) {
  wired_moqt_on_session(hub, s, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl = moqtrun_test_last_kind(1)->stream_id;
  wired_moqt_on_stream_data(
      hub, s, ctrl,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
}

/* OBJECT_DATAGRAM (draft-ietf-moq-transport-19 11.3.1) on the chat track:
 * Type 0x08 (DEFAULT_PRIORITY -- no Priority field), Track Alias 1 (the
 * golden PUBLISH's declared alias), Group 0, Object 5, payload "hi". */
static const u8 MOQTRUN_TEST_DG_CHAT[] = {0x08, 0x01, 0x00, 0x05, 'h', 'i'};

/* One chat subscriber receives the publisher's datagram byte-identical
 * (verbatim relay, no re-encode), counted on stat_dg_sent. */
static void test_moqtrun_dg_relays_identical_bytes_to_subscriber(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);

  moqtrun_test_reset(); /* only observe the relay's own calls */
  wired_moqt_on_datagram(
      &hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));

  CHECK(moqtrun_test_count_kind(9) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(9);
  CHECK(sent != 0);
  if (!sent) return;
  CHECK(sent->s == SESS_B);
  CHECK(sent->payload_len == sizeof MOQTRUN_TEST_DG_CHAT);
  for (usz i = 0; i < sizeof MOQTRUN_TEST_DG_CHAT; i++)
    CHECK(sent->payload[i] == MOQTRUN_TEST_DG_CHAT[i]);
  CHECK(hub.stat_dg_sent == 1);
  CHECK(hub.stat_dg_drop == 0 && hub.stat_dg_bad == 0);
}

/* Three subscribers each receive their own identical copy -- the datagram
 * fan-out reaches every active subscriber, like the stream relay's. */
static void test_moqtrun_dg_relays_to_all_three_subscribers(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);
  moqtrun_test_subscribe_chat(&hub, SESS_C);
  moqtrun_test_subscribe_chat(&hub, SESS_D);

  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));

  CHECK(moqtrun_test_count_kind(9) == 3);
  int seen_b = 0, seen_c = 0, seen_d = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 9) continue;
    CHECK(g_calls[i].payload_len == sizeof MOQTRUN_TEST_DG_CHAT);
    for (usz j = 0; j < sizeof MOQTRUN_TEST_DG_CHAT; j++)
      CHECK(g_calls[i].payload[j] == MOQTRUN_TEST_DG_CHAT[j]);
    if (g_calls[i].s == SESS_B) seen_b = 1;
    if (g_calls[i].s == SESS_C) seen_c = 1;
    if (g_calls[i].s == SESS_D) seen_d = 1;
  }
  CHECK(seen_b && seen_c && seen_d);
  CHECK(hub.stat_dg_sent == 3);
}

/* A datagram on the chat track's alias goes only to the chat subscriber,
 * never to the audio track's subscriber (alias selects the track). */
static void test_moqtrun_dg_chat_alias_only_to_chat_subscriber(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  u64 ctrl_a = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);

  moqtrun_test_subscribe_chat(&hub, SESS_B);
  wired_moqt_on_session(&hub, SESS_C, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_c = moqtrun_test_last_kind(1)->stream_id;
  u8  sub_audio[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_audio_n = moqtrun_test_subscribe_audio_msg(sub_audio);
  wired_moqt_on_stream_data(
      &hub, SESS_C, ctrl_c, wired_span_of(sub_audio, sub_audio_n), 0);

  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));

  CHECK(moqtrun_test_count_kind(9) == 1);
  CHECK(moqtrun_test_last_kind(9) && moqtrun_test_last_kind(9)->s == SESS_B);
}

/* A datagram whose Track Alias matches none of the sending peer's tracks
 * is dropped whole on stat_dg_bad, sent nowhere. */
static void test_moqtrun_dg_unknown_alias_counts_bad(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);

  moqtrun_test_reset();
  static const u8 dg[] = {0x08, 0x09 /* alias 9: nobody's */, 0x00, 0x05, 'h'};
  wired_moqt_on_datagram(&hub, SESS_A, wired_span_of(dg, sizeof dg));

  CHECK(g_n_calls == 0);
  CHECK(hub.stat_dg_bad == 1);
  CHECK(hub.stat_dg_sent == 0 && hub.stat_dg_drop == 0);
}

/* A datagram moqdg_take refuses (Type 0x18: reserved bit 4 set, a
 * VIOLATION per 11.3.1) is dropped whole on stat_dg_bad -- the draft says
 * MUST close the session, but this hub's io table has no close operation
 * (see wired_moqt_on_datagram's doc). */
static void test_moqtrun_dg_malformed_counts_bad(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);

  moqtrun_test_reset();
  static const u8 dg[] = {0x18, 0x01, 0x00, 0x05, 'h', 'i'};
  wired_moqt_on_datagram(&hub, SESS_A, wired_span_of(dg, sizeof dg));

  CHECK(g_n_calls == 0);
  CHECK(hub.stat_dg_bad == 1);
  CHECK(hub.stat_dg_sent == 0 && hub.stat_dg_drop == 0);
}

/* The MIDDLE subscriber's send_datagram is refused: the other two still
 * get their copy (per-subscriber independence), and the one loss is
 * counted on stat_dg_drop, never silent. */
static void test_moqtrun_dg_one_of_three_refused(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);
  moqtrun_test_subscribe_chat(&hub, SESS_C);
  moqtrun_test_subscribe_chat(&hub, SESS_D);

  moqtrun_test_reset();
  g_send_dg_reject_sess = SESS_C; /* only C's send_datagram is refused */
  wired_moqt_on_datagram(
      &hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));

  CHECK(moqtrun_test_count_kind(9) == 3); /* all three attempted */
  CHECK(hub.stat_dg_sent == 2);
  CHECK(hub.stat_dg_drop == 1);
}

/* A subscriber whose session closed is skipped: no late delivery, no
 * dangling send to a dead session. */
static void test_moqtrun_dg_closed_subscription_skipped(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);
  moqtrun_test_subscribe_chat(&hub, SESS_C);
  wired_moqt_on_session_close(&hub, SESS_C);

  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));

  CHECK(moqtrun_test_count_kind(9) == 1);
  CHECK(moqtrun_test_last_kind(9) && moqtrun_test_last_kind(9)->s == SESS_B);
  CHECK(hub.stat_dg_sent == 1);
}

/* A datagram from a session the hub never registered is a no-op: nothing
 * sent, no counter moves (not even stat_dg_bad -- there is no peer whose
 * tracks could judge the alias). */
static void test_moqtrun_dg_unregistered_session_noop(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);

  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &hub, SESS_D /* never registered */,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));

  CHECK(g_n_calls == 0);
  CHECK(hub.stat_dg_sent == 0 && hub.stat_dg_drop == 0);
  CHECK(hub.stat_dg_bad == 0);
}

/* An io table built without the send_datagram entry (0 -- an older
 * positional initializer): the datagram path must not dereference it.
 * Reaching this far without a crash IS the check; nothing is counted. */
static void test_moqtrun_dg_null_send_datagram_is_noop(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_io  io = moqtrun_test_io();
  io.send_datagram  = 0;
  wired_moqt_init(&hub, io);
  moqtrun_test_publish_alice(&hub);
  moqtrun_test_subscribe_chat(&hub, SESS_B);

  moqtrun_test_reset();
  wired_moqt_on_datagram(
      &hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));

  CHECK(g_n_calls == 0);
  CHECK(hub.stat_dg_sent == 0 && hub.stat_dg_drop == 0);
  CHECK(hub.stat_dg_bad == 0);
}

/* ===================== 10. reliable relay (ring-backed)
 * ===================== */

/* Makes every track reliable (any alias < 100) and establishes the audio
 * relay: SESS_A publishing chat+audio, SESS_B subscribed to audio, first
 * Object delivered on publisher stream 999 -- returns SESS_B's relay
 * stream id. The reliable twin of moqtrun_test_start_busy_fixture. */
static u64 moqtrun_test_start_reliable_fixture(wired_moqt_hub* hub) {
  moqtrun_test_reset();
  wired_moqt_init(hub, moqtrun_test_io());
  hub->reliable_alias_limit = 100; /* audio's alias 2 < 100: reliable */
  moqtrun_test_setup_audio_relay(hub);
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  return moqtrun_test_last_kind(5)->stream_id;
}

/* A refused reliable-relay send is retried from the ring on a later tick:
 * the retried round carries the same bytes as the refused one, nothing is
 * counted as a lossy drop, and once accepted no duplicate follows. */
static void test_moqt_reliable_relay_retries_refused_send(void) {
  wired_moqt_hub hub;
  u64            relay_sid = moqtrun_test_start_reliable_fixture(&hub);

  moqtrun_test_reset();
  g_stream_send_reject_n = 1;
  moqtrun_test_send_audio_round(&hub, 999, 9);
  CHECK(moqtrun_test_count_kind(3) == 1); /* attempted and refused */
  const moqtrun_test_call* refused = moqtrun_test_last_kind(3);
  CHECK(refused->stream_id == relay_sid);
  usz round_n = refused->payload_len;
  u8  round[MOQTRUN_TEST_MAX_PAYLOAD];
  for (usz i = 0; i < round_n; i++) round[i] = refused->payload[i];
  CHECK(hub.stat_relay_drop == 0); /* a held byte is not a dropped byte */

  moqtrun_test_reset();
  wired_moqt_tick(&hub, 5);
  CHECK(moqtrun_test_count_kind(3) == 1); /* retried, not forgotten */
  const moqtrun_test_call* retried = moqtrun_test_last_kind(3);
  CHECK(retried->stream_id == relay_sid);
  CHECK(retried->payload_len == round_n);
  for (usz i = 0; i < round_n; i++) CHECK(retried->payload[i] == round[i]);

  moqtrun_test_reset();
  wired_moqt_tick(&hub, 6); /* accepted above: nothing left to resend */
  CHECK(moqtrun_test_count_kind(3) == 0);
}

/* Registers sess and SUBSCRIBEs it to the audio track. */
static void moqtrun_test_subscribe_audio_as(
    wired_moqt_hub* hub, wired_wt_session* sess) {
  wired_moqt_on_session(hub, sess, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl = moqtrun_test_last_kind(1)->stream_id;
  u8  sub[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = moqtrun_test_subscribe_audio_msg(sub);
  wired_moqt_on_stream_data(hub, sess, ctrl, wired_span_of(sub, n), 0);
}

/* The two-subscriber reliable fixture: like moqtrun_test_start_reliable_
 * fixture but with SESS_C also subscribed before the relay starts,
 * returning each subscriber's relay stream id. */
static void moqtrun_test_start_reliable_two_subs(
    wired_moqt_hub* hub, u64* sid_b, u64* sid_c) {
  moqtrun_test_reset();
  wired_moqt_init(hub, moqtrun_test_io());
  hub->reliable_alias_limit = 100;     /* audio's alias 2 < 100: reliable */
  moqtrun_test_setup_audio_relay(hub); /* subscribes SESS_B */
  moqtrun_test_subscribe_audio_as(hub, SESS_C);
  moqtrun_test_reset();
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 5) continue;
    if (g_calls[i].s == SESS_B) *sid_b = g_calls[i].stream_id;
    if (g_calls[i].s == SESS_C) *sid_c = g_calls[i].stream_id;
  }
}

/* Concatenates the payloads of every recorded stream_send addressed to
 * sess into out (bounded by the caller); returns the total length. */
static usz moqtrun_test_concat_sends(wired_wt_session* sess, u8* out, usz cap) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 3 || g_calls[i].s != sess) continue;
    for (usz b = 0; b < g_calls[i].payload_len && n < cap; b++)
      out[n++] = g_calls[i].payload[b];
  }
  return n;
}

/* One large header-less Object round (payload_n bytes of value v) on
 * publisher stream pub_sid: the watermark tests must fill the ring
 * faster than a refused subscriber drains it, so rounds are ring-scale
 * (static staging: MOQTRUN_TEST_MAX_PAYLOAD is far too small). */
static void moqtrun_test_send_big_round(
    wired_moqt_hub* hub, u64 pub_sid, u8 v, usz payload_n) {
  static u8 payload[WIRED_MOQTREL_ROUND_MAX];
  static u8 buf[WIRED_MOQTREL_ROUND_MAX + 16];
  for (usz i = 0; i < payload_n; i++) payload[i] = v;
  usz off = 0;
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, 1,
      wired_span_of(payload, payload_n));
  wired_moqt_on_stream_data(hub, SESS_A, pub_sid, wired_span_of(buf, off), 0);
}

/* The publisher's receive credit is held once the ring nears capacity
 * (a refusing subscriber pins reclaim), exactly once -- and released,
 * exactly once, when later ticks drain the backlog past the low
 * watermark. */
static void test_moqt_reliable_relay_holds_then_releases_publisher(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_reliable_fixture(&hub);

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_B; /* the subscriber stops accepting */
  for (u8 v = 0; v < 3; v++) moqtrun_test_send_big_round(&hub, 999, v, 16000);
  CHECK(moqtrun_test_count_kind(10) == 0); /* 48009 used: under watermark */
  moqtrun_test_send_big_round(&hub, 999, 3, 16000);
  CHECK(moqtrun_test_count_kind(10) == 1); /* 64012 used: hold lands */
  const moqtrun_test_call* hold = moqtrun_test_last_kind(10);
  CHECK(hold->fin == 1 && hold->s == SESS_A && hold->stream_id == 999);
  CHECK(hub.stat_rel_overflow == 0);

  g_stream_send_reject_sess = 0; /* the subscriber drains again */
  moqtrun_test_reset();
  wired_moqt_tick(&hub, 1); /* 16384 of 64012 drained */
  wired_moqt_tick(&hub, 2); /* 32768 drained: still above low watermark */
  CHECK(moqtrun_test_count_kind(10) == 0);
  wired_moqt_tick(&hub, 3); /* 49152 drained, 14860 left: released */
  CHECK(moqtrun_test_count_kind(10) == 1);
  const moqtrun_test_call* rel = moqtrun_test_last_kind(10);
  CHECK(rel->fin == 0 && rel->s == SESS_A && rel->stream_id == 999);

  moqtrun_test_reset();
  wired_moqt_tick(&hub, 4); /* the tail drains; no second release */
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_count_kind(10) == 0);
}

/* A fast and a slow subscriber end up with the SAME complete byte
 * sequence: the slow one's refused rounds stay in the ring (undamaged by
 * the fast one's progress) and drain in order once it accepts again. */
static void test_moqt_reliable_relay_two_speed_subs_no_loss(void) {
  wired_moqt_hub hub;
  u64            sid_b = 0, sid_c = 0;
  moqtrun_test_start_reliable_two_subs(&hub, &sid_b, &sid_c);
  CHECK(sid_b != 0 && sid_c != 0 && sid_b != sid_c);

  u8  exp[64];
  usz exp_n = 0;
  for (u8 v = 1; v <= 3; v++) {
    wired_span p = wired_span_of(&v, 1);
    moqdata_obj_put(wired_mspan_of(exp, sizeof exp), &exp_n, 1, p);
  }

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_C; /* C falls behind, B keeps up */
  for (u8 v = 1; v <= 3; v++) moqtrun_test_send_audio_round(&hub, 999, v);
  u8  got_b[64];
  usz got_b_n = moqtrun_test_concat_sends(SESS_B, got_b, sizeof got_b);
  CHECK(got_b_n == exp_n);
  for (usz i = 0; i < exp_n; i++) CHECK(got_b[i] == exp[i]);

  g_stream_send_reject_sess = 0; /* C accepts again */
  moqtrun_test_reset();
  wired_moqt_tick(&hub, 1);
  CHECK(moqtrun_test_count_kind(3) == 1); /* one catch-up round, C only */
  u8  got_c[64];
  usz got_c_n = moqtrun_test_concat_sends(SESS_C, got_c, sizeof got_c);
  CHECK(got_c_n == exp_n); /* the whole backlog, byte-identical */
  for (usz i = 0; i < exp_n; i++) CHECK(got_c[i] == exp[i]);
}

/* A subscriber that leaves (session close) stops pinning the ring: the
 * next tick reclaims past its cursor, releases the publisher hold it
 * caused, and the remaining subscriber keeps being served. */
static void test_moqt_reliable_relay_sub_leave_unblocks_ring(void) {
  wired_moqt_hub hub;
  u64            sid_b = 0, sid_c = 0;
  moqtrun_test_start_reliable_two_subs(&hub, &sid_b, &sid_c);

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_C; /* C stops accepting and pins head */
  for (u8 v = 0; v < 4; v++) moqtrun_test_send_big_round(&hub, 999, v, 16000);
  CHECK(moqtrun_test_count_kind(10) == 1); /* the pinned ring held */
  CHECK(moqtrun_test_last_kind(10)->fin == 1);

  wired_moqt_on_session_close(&hub, SESS_C);
  moqtrun_test_reset();
  wired_moqt_tick(&hub, 1);
  CHECK(moqtrun_test_count_kind(10) == 1); /* leaver unpins: released */
  CHECK(moqtrun_test_last_kind(10)->fin == 0);

  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 9); /* B is still served */
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->s == SESS_B);
  CHECK(moqtrun_test_last_kind(3)->stream_id == sid_b);
}

/* A subscriber with pending bytes and no accepted send for
 * WIRED_MOQTREL_STALL_MS is shed exactly once (stream_reset, counted on
 * stat_rel_stall): its cursor stops pinning the ring (the hold it caused
 * releases) and the healthy subscriber still finishes with its FIN. */
static void test_moqt_reliable_relay_sheds_stalled_sub(void) {
  wired_moqt_hub hub;
  u64            sid_b = 0, sid_c = 0;
  moqtrun_test_start_reliable_two_subs(&hub, &sid_b, &sid_c);

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_C; /* C accepts nothing from t=0 on */
  for (u8 v = 0; v < 4; v++) moqtrun_test_send_big_round(&hub, 999, v, 16000);
  CHECK(moqtrun_test_count_kind(10) == 1); /* C pins the ring: held */

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_C; /* reset cleared the knob: re-arm */
  wired_moqt_tick(&hub, WIRED_MOQTREL_STALL_MS / 2); /* not yet stalled */
  CHECK(moqtrun_test_count_kind(7) == 0);
  CHECK(hub.stat_rel_stall == 0);

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_C;
  wired_moqt_tick(&hub, WIRED_MOQTREL_STALL_MS + 1); /* stall clock expires */
  CHECK(moqtrun_test_count_kind(7) == 1);            /* C's stream is reset */
  CHECK(moqtrun_test_last_kind(7)->s == SESS_C);
  CHECK(moqtrun_test_last_kind(7)->stream_id == sid_c);
  CHECK(hub.stat_rel_stall == 1);
  CHECK(moqtrun_test_count_kind(10) == 1); /* shed unpinned: released */
  CHECK(moqtrun_test_last_kind(10)->fin == 0);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(0, 0), 1); /* bare publisher FIN */
  CHECK(moqtrun_test_count_kind(6) == 1);         /* B closes; C never does */
  CHECK(moqtrun_test_last_kind(6)->s == SESS_B);
  CHECK(moqtrun_test_last_kind(6)->stream_id == sid_b);
  CHECK(hub.rel_pool[0].in_use == 0); /* B done + C shed: pool returned */
  CHECK(hub.stat_rel_stall == 1);     /* shed once, not once per tick */
}

static usz moqtrun_test_rings_in_use(const wired_moqt_hub* hub) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTREL_POOL; i++)
    if (hub->rel_pool[i].in_use) n++;
  return n;
}

/* A finished ring (publisher FIN forwarded to every cursor) returns to
 * the pool: with all four rings bound, closing one stream frees exactly
 * one ring, and the next fresh reliable stream claims it instead of
 * falling back (stat_relay_full stays 0). */
static void test_moqt_reliable_relay_pool_returns_after_all_done(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_reliable_fixture(&hub); /* stream 999: first ring */
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  for (u64 sid = 1003; sid <= 1011; sid += 4) /* three more streams */
    wired_moqt_on_stream_data(
        &hub, SESS_A, sid, wired_span_of(first, first_n), 0);
  CHECK(moqtrun_test_rings_in_use(&hub) == WIRED_MOQTREL_POOL);
  CHECK(hub.stat_relay_full == 0);

  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(0, 0), 1); /* finish stream 999 */
  CHECK(moqtrun_test_rings_in_use(&hub) == WIRED_MOQTREL_POOL - 1);

  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1015, wired_span_of(first, first_n), 0);
  CHECK(moqtrun_test_rings_in_use(&hub) == WIRED_MOQTREL_POOL);
  CHECK(hub.stat_relay_full == 0); /* the returned ring, not the fallback */
}

/* While rings are still draining (no publisher FIN yet), none may be
 * stolen: a fresh reliable stream on ANOTHER track finds the pool dry,
 * counts stat_relay_full, and relays lossily (rel_idx -1) -- the four
 * bound rings stay bound. */
static void test_moqt_reliable_relay_pool_kept_while_sub_drains(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  hub.reliable_alias_limit = 100; /* chat, audio, AND screen reliable */
  u64 ctrl_a               = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);
  moqtrun_test_publish_alice_screen(&hub, ctrl_a);
  wired_moqt_on_session(&hub, SESS_B, wired_span_of(0, 0), wired_span_of(0, 0));
  u64 ctrl_b = moqtrun_test_last_kind(1)->stream_id;
  u8  sub[MOQTRUN_TEST_MAX_PAYLOAD];
  usz sub_n = moqtrun_test_subscribe_audio_msg(sub);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, wired_span_of(sub, sub_n), 0);
  sub_n = moqtrun_test_subscribe_screen_msg(sub);
  wired_moqt_on_stream_data(&hub, SESS_B, ctrl_b, wired_span_of(sub, sub_n), 0);

  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  for (u64 sid = 999; sid <= 1011; sid += 4) /* audio takes every ring */
    wired_moqt_on_stream_data(
        &hub, SESS_A, sid, wired_span_of(first, first_n), 0);
  CHECK(moqtrun_test_rings_in_use(&hub) == WIRED_MOQTREL_POOL);
  CHECK(hub.stat_relay_full == 0);

  usz scr_n = moqtrun_test_subgroup_with_alias(0x03, first);
  moqtrun_test_reset();
  wired_moqt_on_stream_data(&hub, SESS_A, 2003, wired_span_of(first, scr_n), 0);
  CHECK(hub.stat_relay_full == 1);        /* the pool miss is counted */
  CHECK(moqtrun_test_count_kind(5) == 1); /* still relayed, lossily */
  CHECK(hub.peers[0].tracks[2].relays[0].rel_idx == -1);
  CHECK(moqtrun_test_rings_in_use(&hub) == WIRED_MOQTREL_POOL);
}

/* A track whose alias is NOT below the limit keeps the pre-existing
 * lossy behavior with the limit set: no ring is bound, a refused round
 * is dropped and counted (never retried by the tick), and sustained
 * refusal still sheds through the busy streak, not the stall clock. */
static void test_moqt_relay_lossy_path_unchanged_for_high_alias(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  hub.reliable_alias_limit = 2; /* audio's alias IS 2: not below it */
  moqtrun_test_setup_audio_relay(&hub);
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  u64 relay_sid = moqtrun_test_last_kind(5)->stream_id;
  CHECK(hub.peers[0].tracks[1].relays[0].rel_idx == -1);
  CHECK(moqtrun_test_rings_in_use(&hub) == 0);

  moqtrun_test_reset();
  g_stream_send_reject_n = 1;
  moqtrun_test_send_audio_round(&hub, 999, 1); /* refused: dropped */
  CHECK(hub.stat_relay_drop == 1);
  moqtrun_test_reset();
  wired_moqt_tick(&hub, 5);
  CHECK(moqtrun_test_count_kind(3) == 0); /* lossy: nothing to retry */

  moqtrun_test_reset();
  g_stream_send_reject_n = WIRED_MOQTRUN_RESET_AFTER_BUSY;
  for (u8 v = 0; v < WIRED_MOQTRUN_RESET_AFTER_BUSY; v++)
    moqtrun_test_send_audio_round(&hub, 999, v);
  CHECK(moqtrun_test_count_kind(7) == 1); /* busy streak shed, as ever */
  CHECK(moqtrun_test_last_kind(7)->stream_id == relay_sid);
  CHECK(hub.stat_relay_reset == 1);
  CHECK(hub.stat_rel_stall == 0 && hub.stat_rel_overflow == 0);
}

/* The closing FIN rides the send that carries the stream's last byte --
 * exactly once, never on an earlier round -- and the finished ring (and
 * its relay entry) returns to the pool. */
static void test_moqt_reliable_relay_fin_after_last_byte(void) {
  wired_moqt_hub hub;
  u64            relay_sid = moqtrun_test_start_reliable_fixture(&hub);

  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 7); /* not last: no FIN yet */
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->fin == 0);

  u8         v = 8;
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz        off = 0;
  wired_span p   = wired_span_of(&v, 1);
  moqdata_obj_put(wired_mspan_of(buf, sizeof buf), &off, 1, p);
  moqtrun_test_reset();
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(buf, off), 1 /* fin with last bytes */);

  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* last = moqtrun_test_last_kind(3);
  CHECK(last->fin == 1);
  CHECK(last->stream_id == relay_sid);
  CHECK(last->payload_len == off);        /* the FIN carried the final bytes */
  CHECK(moqtrun_test_count_kind(6) == 0); /* no separate byte-less FIN */
  CHECK(hub.rel_pool[0].in_use == 0);     /* ring back in the pool */
  CHECK(hub.peers[0].tracks[1].relays[0].in_use == 0);

  moqtrun_test_reset();
  wired_moqt_tick(&hub, 7); /* done: no duplicate FIN, no resend */
  CHECK(moqtrun_test_count_kind(3) == 0 && moqtrun_test_count_kind(6) == 0);
}

/* Every subscriber left before the publisher's FIN: the ring returns to
 * the pool (nothing left to retry) but the relay entry stays bound, so
 * later deliveries on the same publisher stream still match it -- routed
 * through the lossy continue (which sends nothing with no subscribers)
 * instead of re-entering fresh-stream classification, where mid-Object
 * bytes decoded as a header could resolve to another track. Only the
 * publisher's FIN frees the entry. */
static void test_moqt_reliable_relay_keeps_entry_after_all_subs_leave(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_reliable_fixture(&hub);
  u64 full_before = hub.stat_relay_full;

  wired_moqt_on_session_close(&hub, SESS_B); /* the only subscriber leaves */
  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 9); /* mid-stream, before FIN */
  CHECK(hub.rel_pool[0].in_use == 0); /* nothing left to retry: returned */
  CHECK(hub.peers[0].tracks[1].relays[0].rel_idx == -1);
  CHECK(hub.peers[0].tracks[1].relays[0].in_use == 1); /* entry kept */
  CHECK(moqtrun_test_count_kind(3) == 0 && moqtrun_test_count_kind(5) == 0);
  CHECK(moqtrun_test_count_kind(4) == 0);
  CHECK(hub.stat_relay_full == full_before); /* never re-classified */

  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 10); /* still matches the entry */
  CHECK(moqtrun_test_count_kind(3) == 0 && moqtrun_test_count_kind(5) == 0);
  CHECK(hub.stat_relay_full == full_before);
  CHECK(hub.peers[0].tracks[1].relays[0].in_use == 1);

  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(0, 0), 1);      /* publisher's FIN */
  CHECK(hub.peers[0].tracks[1].relays[0].in_use == 0); /* now it frees */
}

/* A reliable stream that starts with no subscriber at all: the first
 * drain (a tick here) returns the never-needed ring but keeps the entry,
 * so the stream's later bytes stay recognized (and silently discarded --
 * no one subscribed) until the publisher's FIN frees it. */
static void test_moqt_reliable_relay_keeps_entry_with_no_subs(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  hub.reliable_alias_limit = 100; /* audio's alias 2 < 100: reliable */
  u64 ctrl_a               = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a);
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  CHECK(hub.rel_pool[0].in_use == 1); /* bound at start */

  wired_moqt_tick(&hub, 1); /* first drain: no cursor was ever attached */
  CHECK(hub.rel_pool[0].in_use == 0);
  CHECK(hub.peers[0].tracks[1].relays[0].rel_idx == -1);
  CHECK(hub.peers[0].tracks[1].relays[0].in_use == 1);

  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 9);
  CHECK(moqtrun_test_count_kind(3) == 0 && moqtrun_test_count_kind(5) == 0);
  CHECK(hub.stat_relay_full == 0); /* never re-classified as fresh */

  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(0, 0), 1);
  CHECK(hub.peers[0].tracks[1].relays[0].in_use == 0);
}

/* A shed subscriber's stream was reset: no later round may stream_send to
 * that stream id -- in particular after the ring returns (its last live
 * cursor left) and the entry falls back to the lossy continue, which
 * would otherwise still see the shed slot's stream as open. The lossy
 * round late-opens the shed subscriber a fresh stream instead. */
static void test_moqt_reliable_relay_never_resends_a_shed_stream(void) {
  wired_moqt_hub hub;
  u64            sid_b = 0, sid_c = 0;
  moqtrun_test_start_reliable_two_subs(&hub, &sid_b, &sid_c);

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_C; /* C accepts nothing from t=0 on */
  moqtrun_test_send_audio_round(&hub, 999, 1);

  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_C; /* reset cleared the knob: re-arm */
  wired_moqt_tick(&hub, WIRED_MOQTREL_STALL_MS + 1); /* C sheds */
  CHECK(moqtrun_test_count_kind(7) == 1);
  CHECK(moqtrun_test_last_kind(7)->stream_id == sid_c);

  wired_moqt_on_session_close(&hub, SESS_B); /* last live cursor leaves */
  wired_moqt_tick(&hub, WIRED_MOQTREL_STALL_MS + 2);
  CHECK(hub.rel_pool[0].in_use == 0); /* ring returned, entry kept */
  CHECK(hub.peers[0].tracks[1].relays[0].in_use == 1);

  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 2); /* lossy continuation now */
  for (usz i = 0; i < g_n_calls; i++)
    CHECK(!(g_calls[i].kind == 3 && g_calls[i].stream_id == sid_c));
  CHECK(moqtrun_test_count_kind(5) == 1); /* C re-opened afresh instead */
  CHECK(moqtrun_test_last_kind(5)->s == SESS_C);
}

/* A publisher that leaves mid-stream (no FIN) gives its bound ring back
 * to the pool: nothing ever drains a dead publisher's relay (the tick
 * skips peers with in_use 0), so without the return each mid-stream
 * disconnect would leak one of the four rings until every new reliable
 * stream silently fell back to lossy. */
static void test_moqt_reliable_relay_returns_ring_when_publisher_leaves(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_reliable_fixture(&hub);
  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_B; /* bytes stay pending in the ring */
  moqtrun_test_send_audio_round(&hub, 999, 9);
  CHECK(moqtrun_test_rings_in_use(&hub) == 1);

  wired_moqt_on_session_close(&hub, SESS_A); /* publisher drops mid-stream */
  CHECK(moqtrun_test_rings_in_use(&hub) == 0);
  CHECK(hub.stat_relay_full == 0);

  moqtrun_test_reset(); /* rejoin + re-PUBLISH: a fresh stream binds again */
  u64 ctrl_a2 = moqtrun_test_publish_alice(&hub);
  moqtrun_test_publish_alice_audio(&hub, ctrl_a2);
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 1999, wired_span_of(first, first_n), 0);
  CHECK(moqtrun_test_rings_in_use(&hub) == 1);
  CHECK(hub.stat_relay_full == 0);
}

/* A re-PUBLISH of the same track name abandons the publisher's old
 * streams and clears their relay entries -- a ring bound to one of those
 * entries must return to the pool with it, not stay in_use forever. */
static void test_moqt_reliable_relay_returns_ring_on_republish(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  hub.reliable_alias_limit = 100; /* audio's alias 2 < 100: reliable */
  u64 ctrl_a               = moqtrun_test_setup_audio_relay(&hub);
  u8  first[MOQTRUN_TEST_MAX_PAYLOAD];
  usz first_n = moqtrun_test_subgroup_with_alias(0x02, first);
  wired_moqt_on_stream_data(
      &hub, SESS_A, 999, wired_span_of(first, first_n), 0);
  moqtrun_test_reset();
  g_stream_send_reject_sess = SESS_B; /* bytes stay pending in the ring */
  moqtrun_test_send_audio_round(&hub, 999, 9);
  CHECK(moqtrun_test_rings_in_use(&hub) == 1);

  moqtrun_test_reset();
  moqtrun_test_publish_alice_audio(&hub, ctrl_a); /* re-PUBLISH same name */
  CHECK(moqtrun_test_rings_in_use(&hub) == 0);
  CHECK(hub.stat_relay_full == 0);
}

/* ===================== 11. reliable relay send budget
 * ===================== */

/* Session credit the send_budget stub reports. A budget test installs the
 * stub on hub.io AFTER its fixture ran, so the fixture's own opening
 * rounds stay unconstrained. */
static usz g_send_budget_val;

static usz moqtrun_test_send_budget(wired_wt_session* s) {
  (void)s;
  return g_send_budget_val;
}

/* A round the session's remaining credit cannot carry (plus the headroom)
 * is deferred -- no stream_send at all, counted on stat_rel_wait -- and
 * retried from the ring once the credit recovers: the retried round
 * carries exactly the deferred bytes, once. */
static void test_moqt_reliable_relay_budget_defers_then_sends_same_span(void) {
  wired_moqt_hub hub;
  u64            relay_sid = moqtrun_test_start_reliable_fixture(&hub);
  hub.io.send_budget       = moqtrun_test_send_budget;

  moqtrun_test_reset();
  g_send_budget_val = 0; /* no credit at all */
  moqtrun_test_send_audio_round(&hub, 999, 9);
  CHECK(moqtrun_test_count_kind(3) == 0); /* deferred: never attempted */
  CHECK(hub.stat_rel_wait == 1);
  CHECK(hub.stat_relay_drop == 0); /* a deferred byte is not a dropped one */

  wired_moqt_tick(&hub, 5); /* still no credit: deferred again */
  CHECK(moqtrun_test_count_kind(3) == 0);
  CHECK(hub.stat_rel_wait == 2);

  u8  exp[MOQTRUN_TEST_MAX_PAYLOAD];
  usz exp_n = 0;
  u8  v     = 9;
  moqdata_obj_put(
      wired_mspan_of(exp, sizeof exp), &exp_n, 1, wired_span_of(&v, 1));
  g_send_budget_val = exp_n + WIRED_MOQTREL_HEADROOM; /* recovered */
  wired_moqt_tick(&hub, 6);
  CHECK(moqtrun_test_count_kind(3) == 1);
  const moqtrun_test_call* sent = moqtrun_test_last_kind(3);
  CHECK(sent->stream_id == relay_sid);
  CHECK(sent->payload_len == exp_n);
  for (usz i = 0; i < exp_n; i++) CHECK(sent->payload[i] == exp[i]);

  moqtrun_test_reset();
  wired_moqt_tick(&hub, 7); /* accepted above: nothing left to resend */
  CHECK(moqtrun_test_count_kind(3) == 0);
}

/* The headroom is inviolable: credit of round + headroom - 1 defers, and
 * exactly round + headroom sends -- a lossy screen-share round sharing
 * the session always finds WIRED_MOQTREL_HEADROOM of credit left. */
static void test_moqt_reliable_relay_budget_leaves_headroom(void) {
  wired_moqt_hub hub;
  moqtrun_test_start_reliable_fixture(&hub);
  hub.io.send_budget = moqtrun_test_send_budget;

  u8  obj[MOQTRUN_TEST_MAX_PAYLOAD];
  usz obj_n = 0;
  u8  v     = 7;
  moqdata_obj_put(
      wired_mspan_of(obj, sizeof obj), &obj_n, 1, wired_span_of(&v, 1));

  moqtrun_test_reset();
  g_send_budget_val = obj_n + WIRED_MOQTREL_HEADROOM - 1; /* one short */
  wired_moqt_on_stream_data(&hub, SESS_A, 999, wired_span_of(obj, obj_n), 0);
  CHECK(moqtrun_test_count_kind(3) == 0);
  CHECK(hub.stat_rel_wait == 1);

  g_send_budget_val = obj_n + WIRED_MOQTREL_HEADROOM; /* exactly enough */
  wired_moqt_tick(&hub, 5);
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->payload_len == obj_n);
  CHECK(hub.stat_rel_wait == 1); /* the boundary send is not a wait */
}

/* An io table without send_budget (0 -- every existing positional
 * initializer) is unconstrained: rounds send immediately and
 * stat_rel_wait never moves. */
static void test_moqt_reliable_relay_no_send_budget_unchanged(void) {
  wired_moqt_hub hub;
  u64            relay_sid = moqtrun_test_start_reliable_fixture(&hub);

  moqtrun_test_reset();
  moqtrun_test_send_audio_round(&hub, 999, 9);
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->stream_id == relay_sid);
  CHECK(hub.stat_rel_wait == 0);
}

void test_moqtrun(void) {
  test_moqtrun_on_session_sends_setup();
  test_moqtrun_on_session_twice_is_idempotent();
  test_moqtrun_publish_replies_request_ok();
  test_moqtrun_subscribe_matching_publish_replies_ok();
  test_moqtrun_subscribe_without_publish_replies_error();
  test_moqtrun_subscribe_fits_every_other_peer();
  test_moqtrun_object_relay_to_subscriber();
  test_moqtrun_object_relay_preserves_bytes();
  test_moqtrun_object_relay_two_subscribers_two_objects();
  test_moqtrun_subscribe_nonzero_timeout_rejected();
  test_moqtrun_subscribe_ok_carries_no_timeout_param();
  test_moqtrun_subscribe_requires_authorization();
  test_moqtrun_subscribe_alias_token_rejected();
  test_moqtrun_unknown_first_type_gets_not_supported();
  test_moqtrun_goaway_on_request_stream_produces_no_reply();
  test_moqtrun_padding_stream_discarded();
  test_moqtrun_peer_publishes_two_tracks();
  test_moqtrun_peer_publishes_three_tracks();
  test_moqtrun_fourth_publish_gets_error();
  test_moqtrun_republish_same_name_reuses_slot();
  test_moqtrun_subscribe_audio_track_replies_ok();
  test_moqtrun_chat_and_audio_get_different_aliases();
  test_moqtrun_chat_object_relays_only_to_chat_subscriber();
  test_moqtrun_chat_object_relays_to_all_three_subscribers();
  test_moqtrun_chat_one_of_three_subscribers_refused();
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
  test_moqtrun_screen_first_object_opens_then_appends();
  test_moqtrun_republish_resets_orphaned_relay_stream();
  test_moqtrun_audio_publisher_fin_closes_and_reopens();
  test_moqtrun_chat_still_uses_send_uni_every_object();
  test_moqtrun_stream_send_rejection_drops_frame_not_fatal();
  test_moqtrun_audio_two_subscribers_independent_streams();
  test_moqtrun_send_uni_failure_counts_open_drop();
  test_moqtrun_relay_table_full_counts();
  test_moqtrun_busy_streak_sheds_after_threshold();
  test_moqtrun_busy_streak_success_resets();
  test_moqtrun_shed_stream_skips_publisher_fin();
  test_moqtrun_busy_shed_isolated_per_subscriber();
  test_moqtrun_shed_refused_retries_next_round();
  test_moqtrun_republish_clears_busy_streak();
  test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes();
  test_moqtrun_audio_split_data_then_bare_fin_closes();
  test_moqtrun_interleaved_chat_messages_close_independently();
  test_moqtrun_late_subscriber_gets_late_opened_stream();
  test_moqtrun_torn_object_held_until_complete();
  test_moqtrun_normalize_forwards_only_whole_objects();
  test_moqtrun_fresh_delivery_tail_held_back();
  test_moqtrun_fresh_torn_first_object_accepted();
  test_moqtrun_fresh_oneshot_no_object_discarded();
  test_moqtrun_frag_overflow_counted();
  test_moqtrun_close_frees_peer_for_reregistration();
  test_moqtrun_close_drops_subscriptions();
  test_moqtrun_duplicate_subscribe_reuses_slot();
  test_moqtrun_republish_reattaches_subscriber();
  test_moqtrun_reattach_survives_nine_subscribed_names();
  test_moqtrun_reconnected_subscriber_is_not_reattached();
  test_moqtrun_publisher_is_not_reattached_to_own_track();
  test_moqtrun_refused_subscribe_is_not_remembered();
  test_moqtrun_close_unknown_session_noop();
  test_moqtrun_close_reregister_churn();
  test_moqtrun_blob_empty_not_published();
  test_moqtrun_blob_wire_too_small();
  test_moqtrun_blob_subscribe_sends_once();
  test_moqtrun_blob_resubscribe_no_resend();
  test_moqtrun_blob_two_peers_each_get_copy();
  test_moqtrun_blob_send_refused_then_retry();
  test_moqtrun_blob_close_then_reconnect_resends();
  test_moqtrun_blob_shadows_peer_track_of_same_name();
  test_moqtrun_live_publish_rejects_bad_args();
  test_moqtrun_live_empty_fragment_rejected();
  test_moqtrun_live_subscribe_sends_current_group();
  test_moqtrun_live_tick_advances_groups();
  test_moqtrun_live_refused_send_retries_then_drops();
  test_moqtrun_live_two_subscribers_independent();
  test_moqtrun_live_resubscribe_no_resend();
  test_moqtrun_live_close_then_reconnect();
  test_moqtrun_live_and_blob_coexist();
  test_moqtrun_dg_relays_identical_bytes_to_subscriber();
  test_moqtrun_dg_relays_to_all_three_subscribers();
  test_moqtrun_dg_chat_alias_only_to_chat_subscriber();
  test_moqtrun_dg_unknown_alias_counts_bad();
  test_moqtrun_dg_malformed_counts_bad();
  test_moqtrun_dg_one_of_three_refused();
  test_moqtrun_dg_closed_subscription_skipped();
  test_moqtrun_dg_unregistered_session_noop();
  test_moqtrun_dg_null_send_datagram_is_noop();
  test_moqt_reliable_relay_retries_refused_send();
  test_moqt_reliable_relay_fin_after_last_byte();
  test_moqt_reliable_relay_holds_then_releases_publisher();
  test_moqt_reliable_relay_two_speed_subs_no_loss();
  test_moqt_reliable_relay_sub_leave_unblocks_ring();
  test_moqt_reliable_relay_sheds_stalled_sub();
  test_moqt_reliable_relay_pool_returns_after_all_done();
  test_moqt_reliable_relay_pool_kept_while_sub_drains();
  test_moqt_relay_lossy_path_unchanged_for_high_alias();
  test_moqt_reliable_relay_keeps_entry_after_all_subs_leave();
  test_moqt_reliable_relay_keeps_entry_with_no_subs();
  test_moqt_reliable_relay_never_resends_a_shed_stream();
  test_moqt_reliable_relay_returns_ring_when_publisher_leaves();
  test_moqt_reliable_relay_returns_ring_on_republish();
  test_moqt_reliable_relay_budget_defers_then_sends_same_span();
  test_moqt_reliable_relay_budget_leaves_headroom();
  test_moqt_reliable_relay_no_send_budget_unchanged();
}
