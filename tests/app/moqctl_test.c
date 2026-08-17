#include "app/moqt/ctl/moqctl.h"

#include "moqt_golden.h"
#include "test.h"

/* @file
 * draft-ietf-moq-transport-19 SS10 Control Message codec tests. Golden byte
 * sequences are pinned in tests/app/moqt_golden.h (generated from
 * examples/moqt_chat/testvectors/moqt_golden.json); this file never hand-
 * types a wire byte sequence for round-trip coverage.
 *
 * Coverage: common envelope, per-message round trips, Message Parameters,
 * Setup Options, GOAWAY, REQUEST_OK, REQUEST_ERROR, FORWARD, Reason Phrase,
 * Location, Track Namespace/Name, Location Filter, grease/unknown-code.
 */

/* ===== TEST 1: common envelope round-trip ===== */

static void test_moqctl_peek_type_setup(void) {
  usz        off = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_setup_impl, G_MOQT_CTL_SETUP_IMPL_LEN), &off,
          &type, &body) == MOQCTL_OK);
  CHECK(type == G_MOQT_CTL_SETUP_IMPL_TYPE);
  CHECK(body.n == G_MOQT_CTL_SETUP_IMPL_MSG_LEN);
  CHECK(off == G_MOQT_CTL_SETUP_IMPL_LEN);
}

/* TEST 2: Message Length / Body mismatch -> VIOLATION. Shrink the
 * declared Length by 1 without touching the body bytes. */
static void test_moqctl_peek_type_length_mismatch(void) {
  u8         buf[32];
  usz        off = 0;
  u64        type;
  wired_span body;

  for (usz i = 0; i < G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN; i++)
    buf[i] = g_moqt_ctl_subscribe_ok_basic[i];
  buf[2] = G_MOQT_CTL_SUBSCRIBE_OK_BASIC_MSG_LEN + 1; /* claim one more byte
                                                          than actually
                                                          present */
  CHECK(
      moqctl_peek_type(
          wired_span_of(buf, G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN), &off, &type,
          &body) == MOQCTL_INSUFFICIENT);
}

/* TEST 3: body cut short mid-message -> INSUFFICIENT. */
static void test_moqctl_peek_type_truncated(void) {
  usz        off = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN - 3),
          &off, &type, &body) == MOQCTL_INSUFFICIENT);
}

/* TEST 4: unknown message type -> UNKNOWN_TYPE. Type 0x2 (REQUEST_
 * UPDATE) is known-but-unimplemented; 0x99 is not in the SS10 table at
 * all. */
static void test_moqctl_peek_type_unknown(void) {
  const u8   in[] = {0x99, 0x01, 0x00, 0x00};
  usz        off  = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_UNKNOWN_TYPE);
}

/* TEST 5: known-but-unimplemented message type is distinguished from an
 * unknown one. REQUEST_UPDATE = 0x2, zero-length body. */
static void test_moqctl_peek_type_known_unimplemented(void) {
  const u8   in[] = {0x02, 0x00, 0x00};
  usz        off  = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
}

/* TEST 6: message total length boundary at 2^16-1. A Length field
 * that itself claims the max is accepted by peek_type as long as the body
 * bytes are actually present; this test only exercises the encoding of
 * the boundary value in the Length field via a minimal SUBSCRIBE_OK. */
static void test_moqctl_peek_type_max_len_field(void) {
  u8         buf[8];
  usz        off = 0;
  u64        type;
  wired_span body;

  buf[0] = 0x04; /* SUBSCRIBE_OK */
  buf[1] = 0xFF;
  buf[2] = 0xFF; /* Length = 65535, but only 2 bytes follow: insufficient */
  CHECK(
      moqctl_peek_type(wired_span_of(buf, 3), &off, &type, &body) ==
      MOQCTL_INSUFFICIENT);
}

/* ===== TEST 7-14: per-message round trip against golden ===== */

static void test_moqctl_setup_roundtrip(void) {
  usz          off = 0;
  u64          type;
  wired_span   body;
  moqctl_setup s;
  u8           out[G_MOQT_CTL_SETUP_IMPL_LEN];
  wired_mspan  ob   = wired_mspan_of(out, sizeof out);
  usz          eoff = 0;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_setup_impl, G_MOQT_CTL_SETUP_IMPL_LEN), &off,
          &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_setup_take(body, &boff, &s) == MOQCTL_OK);
    CHECK(boff == body.n);
  }
  CHECK(!s.has_path);
  CHECK(!s.has_authority);
  CHECK(s.has_implementation);
  CHECK(s.implementation.n == 7);
  CHECK(s.implementation.p[0] == 'w');

  CHECK(moqvi_put(ob, &eoff, type));
  {
    usz         len_at = eoff;
    usz         body_at;
    wired_mspan full = wired_mspan_of(out, sizeof out);
    eoff += 2; /* placeholder for Length */
    body_at = eoff;
    CHECK(moqctl_setup_encode(full, &eoff, &s));
    out[len_at]     = (u8)((eoff - body_at) >> 8);
    out[len_at + 1] = (u8)(eoff - body_at);
  }
  CHECK(eoff == G_MOQT_CTL_SETUP_IMPL_LEN);
  for (usz i = 0; i < eoff; i++) CHECK(out[i] == g_moqt_ctl_setup_impl[i]);
}

/* Shared re-encode helper for the remaining messages: writes Type (vi64) +
 * placeholder Length + calls encode_body, then backpatches Length. */
typedef int (*moqctl_encode_body_fn)(wired_mspan, usz*, const void*);

static void moqctl_reencode(
    u8*                   out,
    usz                   cap,
    u64                   type,
    moqctl_encode_body_fn body_fn,
    const void*           msg,
    usz*                  out_len) {
  wired_mspan full = wired_mspan_of(out, cap);
  usz         eoff = 0;
  usz         len_at;
  usz         body_at;
  CHECK(moqvi_put(full, &eoff, type));
  len_at = eoff;
  eoff += 2;
  body_at = eoff;
  CHECK(body_fn(full, &eoff, msg));
  out[len_at]     = (u8)((eoff - body_at) >> 8);
  out[len_at + 1] = (u8)(eoff - body_at);
  *out_len        = eoff;
}

static int moqctl_encode_subscribe(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_encode(buf, off, m);
}

static void test_moqctl_subscribe_roundtrip(void) {
  usz              off = 0;
  u64              type;
  wired_span       body;
  moqctl_subscribe m;
  u8               out[G_MOQT_CTL_SUBSCRIBE_BASIC_LEN];
  usz              out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_subscribe_take(body, &boff, &m) == MOQCTL_OK);
    CHECK(boff == body.n);
  }
  CHECK(m.request_id == 0);
  CHECK(m.name.ns.n == 2);
  CHECK(m.name.ns.fields[0].n == 4);
  CHECK(m.name.ns.fields[0].p[0] == 'c');
  CHECK(m.name.ns.fields[1].n == 5);
  CHECK(m.name.name.n == 5);
  CHECK(m.name.name.p[0] == 'a');
  CHECK(m.params.n == 0);

  moqctl_reencode(out, sizeof out, type, moqctl_encode_subscribe, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_SUBSCRIBE_BASIC_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_subscribe_basic[i]);
}

static int moqctl_encode_subscribe_ok(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_ok_encode(buf, off, m);
}

static void test_moqctl_subscribe_ok_roundtrip(void) {
  usz                 off = 0;
  u64                 type;
  wired_span          body;
  moqctl_subscribe_ok m;
  u8                  out[G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN];
  usz                 out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_subscribe_ok_basic, G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_subscribe_ok_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.track_alias == 1);
  CHECK(m.params.n == 0);
  CHECK(m.track_properties.n == 0);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_subscribe_ok, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_subscribe_ok_basic[i]);
}

static int moqctl_encode_publish(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_encode(buf, off, m);
}

static void test_moqctl_publish_roundtrip(void) {
  usz            off = 0;
  u64            type;
  wired_span     body;
  moqctl_publish m;
  u8             out[G_MOQT_CTL_PUBLISH_BASIC_LEN];
  usz            out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_publish_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.request_id == 0);
  CHECK(m.name.ns.n == 2);
  CHECK(m.track_alias == 1);
  CHECK(m.params.n == 0);
  CHECK(m.track_properties.n == 0);

  moqctl_reencode(out, sizeof out, type, moqctl_encode_publish, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_PUBLISH_BASIC_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_publish_basic[i]);
}

static int moqctl_encode_request_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_ok_encode(buf, off, m);
}

static void test_moqctl_request_ok_roundtrip(void) {
  usz               off = 0;
  u64               type;
  wired_span        body;
  moqctl_request_ok m;
  u8                out[G_MOQT_CTL_REQUEST_OK_BASIC_LEN];
  usz               out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_request_ok_basic, G_MOQT_CTL_REQUEST_OK_BASIC_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_request_ok_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.params.n == 0);
  CHECK(m.track_properties.n == 0);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_request_ok, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_REQUEST_OK_BASIC_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_request_ok_basic[i]);
}

static int moqctl_encode_request_error(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode(buf, off, m);
}

static void test_moqctl_request_error_roundtrip(void) {
  usz                  off = 0;
  u64                  type;
  wired_span           body;
  moqctl_request_error m;
  u8                   out[G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN];
  usz                  out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_request_error_not_supported,
              G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_request_error_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.error_code == MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(m.retry_interval == 0);
  CHECK(m.reason.n == 13);
  CHECK(!m.has_redirect);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_request_error, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_request_error_not_supported[i]);
}

static int moqctl_encode_publish_done(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_done_encode(buf, off, m);
}

static void test_moqctl_publish_done_roundtrip(void) {
  usz                 off = 0;
  u64                 type;
  wired_span          body;
  moqctl_publish_done m;
  u8                  out[G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN];
  usz                 out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(
              g_moqt_ctl_publish_done_track_ended,
              G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_publish_done_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.status_code == MOQCTL_DONE_TRACK_ENDED);
  CHECK(m.stream_count == 2);
  CHECK(m.reason.n == 0);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_publish_done, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_publish_done_track_ended[i]);
}

static int moqctl_encode_goaway(wired_mspan buf, usz* off, const void* m) {
  return moqctl_goaway_encode(buf, off, m);
}

static void test_moqctl_goaway_roundtrip(void) {
  usz           off = 0;
  u64           type;
  wired_span    body;
  moqctl_goaway m;
  u8            out[G_MOQT_CTL_GOAWAY_EMPTY_LEN];
  usz           out_len;

  CHECK(
      moqctl_peek_type(
          wired_span_of(g_moqt_ctl_goaway_empty, G_MOQT_CTL_GOAWAY_EMPTY_LEN),
          &off, &type, &body) == MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(moqctl_goaway_take(body, &boff, &m) == MOQCTL_OK);
  }
  CHECK(m.new_session_uri.n == 0);
  CHECK(m.timeout == 0);

  moqctl_reencode(out, sizeof out, type, moqctl_encode_goaway, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_GOAWAY_EMPTY_LEN);
  for (usz i = 0; i < out_len; i++) CHECK(out[i] == g_moqt_ctl_goaway_empty[i]);
}

/* ===== TEST: GOAWAY New Session URI 8192 boundary ===== */

static void test_moqctl_goaway_uri_boundary(void) {
  u8            buf_ok[3 + MOQCTL_MAX_URI_LEN + 4];
  u8            buf_reject[3 + MOQCTL_MAX_URI_LEN + 5];
  usz           at;
  moqctl_goaway m;

  /* 8192 accepted: len varint(2B, 0x9f 0x40 encodes 8192) + 8192 bytes +
   * timeout varint(1B, 0x00). moqvi_put proves the length encoding; we
   * only need decode acceptance here. */
  at = 0;
  CHECK(moqvi_put(wired_mspan_of(buf_ok, sizeof buf_ok), &at, 8192));
  for (usz i = 0; i < MOQCTL_MAX_URI_LEN; i++) buf_ok[at + i] = 'a';
  at += MOQCTL_MAX_URI_LEN;
  CHECK(moqvi_put(wired_mspan_of(buf_ok, sizeof buf_ok), &at, 0));
  {
    usz off = 0;
    CHECK(moqctl_goaway_take(wired_span_of(buf_ok, at), &off, &m) == MOQCTL_OK);
    CHECK(m.new_session_uri.n == MOQCTL_MAX_URI_LEN);
  }

  /* 8193 rejected */
  at = 0;
  CHECK(moqvi_put(
      wired_mspan_of(buf_reject, sizeof buf_reject), &at,
      MOQCTL_MAX_URI_LEN + 1));
  for (usz i = 0; i < MOQCTL_MAX_URI_LEN + 1; i++) buf_reject[at + i] = 'a';
  at += MOQCTL_MAX_URI_LEN + 1;
  {
    usz off = 0;
    CHECK(
        moqctl_goaway_take(wired_span_of(buf_reject, at), &off, &m) ==
        MOQCTL_VIOLATION);
  }
}

/* ===== TEST: Reason Phrase 1024 boundary ===== */

static void test_moqctl_reason_boundary(void) {
  u8            buf_ok[3 + MOQCTL_MAX_REASON_LEN];
  u8            buf_reject[3 + MOQCTL_MAX_REASON_LEN + 1];
  usz           at;
  moqctl_reason r;

  at = 0;
  CHECK(moqvi_put(wired_mspan_of(buf_ok, sizeof buf_ok), &at, 1024));
  for (usz i = 0; i < 1024; i++) buf_ok[at + i] = 'x';
  at += 1024;
  {
    usz off = 0;
    CHECK(moqctl_reason_take(wired_span_of(buf_ok, at), &off, &r) == MOQCTL_OK);
    CHECK(r.n == 1024);
  }

  at = 0;
  CHECK(moqvi_put(wired_mspan_of(buf_reject, sizeof buf_reject), &at, 1025));
  for (usz i = 0; i < 1025; i++) buf_reject[at + i] = 'x';
  at += 1025;
  {
    usz off = 0;
    CHECK(
        moqctl_reason_take(wired_span_of(buf_reject, at), &off, &r) ==
        MOQCTL_VIOLATION);
  }
}

/* ===== TEST: Location encode/compare ===== */

static void test_moqctl_location_roundtrip_and_order(void) {
  u8         buf[32];
  usz        off = 0;
  moqctl_loc a   = {5, 10};
  moqctl_loc b   = {5, 11};
  moqctl_loc c   = {6, 0};
  moqctl_loc out;

  CHECK(moqctl_loc_put(wired_mspan_of(buf, sizeof buf), &off, a));
  {
    usz roff = 0;
    CHECK(moqctl_loc_take(wired_span_of(buf, off), &roff, &out) == MOQCTL_OK);
    CHECK(out.group == a.group);
    CHECK(out.object == a.object);
  }
  CHECK(moqctl_loc_less(a, b));
  CHECK(moqctl_loc_less(b, c));
  CHECK(!moqctl_loc_less(b, a));
}

/* ===== TEST: Track Namespace / Full Track Name ===== */

static void test_moqctl_ftn_decode_basic(void) {
  moqctl_ftn f;
  usz        off = 0;

  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_full_track_name_basic,
              G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN),
          &off, &f) == MOQCTL_OK);
  CHECK(off == G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN);
  CHECK(f.ns.n == 2);
  CHECK(f.ns.fields[0].n == 4);
  CHECK(f.ns.fields[1].n == 5);
  CHECK(f.name.n == 5);
}

/* Field Length 0 -> PROTOCOL_VIOLATION. */
static void test_moqctl_ns_field_len_zero_rejected(void) {
  moqctl_ns ns;
  usz       off = 0;

  CHECK(
      moqctl_ns_take(
          wired_span_of(
              g_moqt_name_ns_field_len_zero_reject,
              G_MOQT_NAME_NS_FIELD_LEN_ZERO_REJECT_LEN),
          &off, &ns) == MOQCTL_VIOLATION);
}

/* 32 fields accepted, 33 rejected. */
static void test_moqctl_ns_fields_32_accept_33_reject(void) {
  moqctl_ns ns;
  usz       off;

  off = 0;
  CHECK(
      moqctl_ns_take(
          wired_span_of(
              g_moqt_name_ns_fields_32_accept,
              G_MOQT_NAME_NS_FIELDS_32_ACCEPT_LEN),
          &off, &ns) == MOQCTL_OK);
  CHECK(ns.n == 32);

  off = 0;
  CHECK(
      moqctl_ns_take(
          wired_span_of(
              g_moqt_name_ns_fields_33_reject,
              G_MOQT_NAME_NS_FIELDS_33_REJECT_LEN),
          &off, &ns) == MOQCTL_VIOLATION);
}

/* Full Track Name 4096 boundary. */
static void test_moqctl_ftn_4096_accept_4097_reject(void) {
  moqctl_ftn f;
  usz        off;

  off = 0;
  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_ftn_4096_accept, G_MOQT_NAME_FTN_4096_ACCEPT_LEN),
          &off, &f) == MOQCTL_OK);

  off = 0;
  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_ftn_4097_reject, G_MOQT_NAME_FTN_4097_REJECT_LEN),
          &off, &f) == MOQCTL_VIOLATION);
}

/* Exact byte comparison, no encoding-dependent shortcuts. */
static void test_moqctl_ftn_eq_exact_bytes(void) {
  moqctl_ftn a, b;
  usz        off;

  off = 0;
  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_full_track_name_basic,
              G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN),
          &off, &a) == MOQCTL_OK);
  off = 0;
  CHECK(
      moqctl_ftn_take(
          wired_span_of(
              g_moqt_name_full_track_name_basic,
              G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN),
          &off, &b) == MOQCTL_OK);
  CHECK(moqctl_ftn_eq(&a, &b));
  b.name.p = (const u8*)"zzzzz";
  CHECK(!moqctl_ftn_eq(&a, &b));
}

/* ===== TEST: Message Parameters ===== */

/* FORWARD (uint8) round trip inside SUBSCRIBE's scope. */
static void test_moqctl_params_forward_roundtrip(void) {
  u8            buf[16];
  usz           off = 0;
  moqctl_params p   = {0};
  moqctl_params out;

  p.items[0].type = MOQCTL_PARAM_FORWARD;
  p.items[0].enc  = MOQCTL_PENC_UINT8;
  p.items[0].u8v  = 0;
  p.n             = 1;

  CHECK(moqctl_params_put(wired_mspan_of(buf, sizeof buf), &off, &p));
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            wired_span_of(buf, off), &roff, MOQCTL_T_SUBSCRIBE, &out) ==
        MOQCTL_OK);
  }
  CHECK(out.n == 1);
  CHECK(out.items[0].type == MOQCTL_PARAM_FORWARD);
  CHECK(out.items[0].u8v == 0);
}

/* Cumulative Parameter Type overflow -> VIOLATION. Two params whose
 * deltas sum past 2^64-1. */
static void test_moqctl_params_type_overflow_violation(void) {
  u8            buf[24];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 2)); /* count */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, MOQCTL_PARAM_FORWARD));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1)); /* value */
  CHECK(
      moqvi_put(wired_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* delta
                                                                     overflow */
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            wired_span_of(buf, off), &roff, MOQCTL_T_SUBSCRIBE, &out) ==
        MOQCTL_VIOLATION);
  }
}

/* Unknown Message Parameter Type -> VIOLATION. */
static void test_moqctl_params_unknown_type_violation(void) {
  u8            buf[8];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x77));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            wired_span_of(buf, off), &roff, MOQCTL_T_SUBSCRIBE, &out) ==
        MOQCTL_VIOLATION);
  }
}

/* Duplicate Parameter Type -> VIOLATION. */
static void test_moqctl_params_duplicate_type_violation(void) {
  u8            buf[16];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 2));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, MOQCTL_PARAM_FORWARD));
  buf[off] = 1;
  off += 1;                                                   /* uint8 value */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0)); /* delta 0
                                                                      -> same
                                                                      type */
  buf[off] = 1;
  off += 1;
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            wired_span_of(buf, off), &roff, MOQCTL_T_SUBSCRIBE, &out) ==
        MOQCTL_VIOLATION);
  }
}

/* Known parameter type outside its allowed message scope ->
 * VIOLATION. FORWARD is legal in SUBSCRIBE/PUBLISH but not SUBSCRIBE_OK. */
static void test_moqctl_params_scope_violation(void) {
  u8            buf[8];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, MOQCTL_PARAM_FORWARD));
  buf[off] = 1;
  off += 1;
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            wired_span_of(buf, off), &roff, MOQCTL_T_SUBSCRIBE_OK, &out) ==
        MOQCTL_VIOLATION);
  }
}

/* SUBGROUP/OBJECT_DELIVERY_TIMEOUT decode as varint, 0 = unset. */
static void test_moqctl_params_delivery_timeout_decode(void) {
  u8            buf[16];
  usz           off = 0;
  moqctl_params out;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(moqvi_put(
      wired_mspan_of(buf, sizeof buf), &off,
      MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));
  {
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            wired_span_of(buf, off), &roff, MOQCTL_T_SUBSCRIBE, &out) ==
        MOQCTL_OK);
  }
  CHECK(out.n == 1);
  CHECK(out.items[0].vi == 0);
}

/* ===== TEST: SETUP Setup Options behaviors ===== */

/* Unknown Setup Option (including a duplicate of it) is ignored. */
static void test_moqctl_setup_unknown_option_ignored(void) {
  u8           buf[16];
  usz          off = 0;
  moqctl_setup s;

  /* two odd, unrecognized option types (0x0B, delta then +0x0A -> 0x15),
   * each carrying one raw byte -- both must be silently ignored. */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x0B));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  buf[off] = 0xAA;
  off += 1;
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0x0A));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1));
  buf[off] = 0xBB;
  off += 1;

  {
    usz soff = 0;
    CHECK(moqctl_setup_take(wired_span_of(buf, off), &soff, &s) == MOQCTL_OK);
  }
  CHECK(!s.has_path);
  CHECK(!s.has_authority);
  CHECK(!s.has_implementation);
}

/* MOQT_IMPLEMENTATION option decode (UTF-8 name+version). Already
 * covered end-to-end by test_moqctl_setup_roundtrip via the golden vector;
 * this test isolates the PATH option instead for independent coverage. */
static void test_moqctl_setup_path_option_decode(void) {
  u8           buf[16];
  usz          off = 0;
  moqctl_setup s;

  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 1)); /* PATH=1 */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 3));
  buf[off]     = '/';
  buf[off + 1] = 'a';
  buf[off + 2] = 'b';
  off += 3;

  {
    usz soff = 0;
    CHECK(moqctl_setup_take(wired_span_of(buf, off), &soff, &s) == MOQCTL_OK);
  }
  CHECK(s.has_path);
  CHECK(s.path.n == 3);
  CHECK(s.path.p[0] == '/');
}

/* ===== TEST: Location Filter ===== */

static void test_moqctl_locfilter_next_group_and_largest(void) {
  const u8         in_ng[] = {0x01};
  const u8         in_lg[] = {0x02};
  usz              off;
  moqctl_locfilter f;

  off = 0;
  CHECK(
      moqctl_locfilter_take(wired_span_of(in_ng, sizeof in_ng), &off, &f) ==
      MOQCTL_OK);
  CHECK(f.type == MOQCTL_FILTER_NEXT_GROUP);
  CHECK(off == 1);

  off = 0;
  CHECK(
      moqctl_locfilter_take(wired_span_of(in_lg, sizeof in_lg), &off, &f) ==
      MOQCTL_OK);
  CHECK(f.type == MOQCTL_FILTER_LARGEST);
}

static void test_moqctl_locfilter_abs_start_and_range_roundtrip(void) {
  u8               buf[32];
  usz              off  = 0;
  moqctl_locfilter f_in = {0};
  moqctl_locfilter f_out;

  f_in.type            = MOQCTL_FILTER_ABS_RANGE;
  f_in.start.group     = 3;
  f_in.start.object    = 0;
  f_in.end_group_delta = 5;

  CHECK(moqctl_locfilter_put(wired_mspan_of(buf, sizeof buf), &off, &f_in));
  {
    usz roff = 0;
    CHECK(
        moqctl_locfilter_take(wired_span_of(buf, off), &roff, &f_out) ==
        MOQCTL_OK);
  }
  CHECK(f_out.type == MOQCTL_FILTER_ABS_RANGE);
  CHECK(f_out.start.group == 3);
  CHECK(f_out.end_group_delta == 5);
}

/* End Group overflow (Start.Group + Delta > 2^64-1) -> VIOLATION. */
static void test_moqctl_locfilter_end_group_overflow_violation(void) {
  u8               buf[24];
  usz              off = 0;
  moqctl_locfilter f;

  CHECK(moqvi_put(
      wired_mspan_of(buf, sizeof buf), &off, MOQCTL_FILTER_ABS_RANGE));
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 5)); /* Group */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0)); /* Object */
  CHECK(
      moqvi_put(wired_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* delta
                                                                     overflow */
  {
    usz roff = 0;
    CHECK(
        moqctl_locfilter_take(wired_span_of(buf, off), &roff, &f) ==
        MOQCTL_VIOLATION);
  }
}

/* Unknown Filter Type -> VIOLATION. */
static void test_moqctl_locfilter_unknown_type_violation(void) {
  const u8         in[] = {0x05};
  usz              off  = 0;
  moqctl_locfilter f;

  CHECK(
      moqctl_locfilter_take(wired_span_of(in, sizeof in), &off, &f) ==
      MOQCTL_VIOLATION);
}

/* ===== TEST: grease / unknown error code normalization ===== */

static void test_moqctl_grease_pattern(void) {
  CHECK(moqctl_is_grease(0x9D));
  CHECK(moqctl_is_grease(0x9D + 0x7f));
  CHECK(moqctl_is_grease(0x9D + 2 * 0x7f));
  CHECK(!moqctl_is_grease(0));
  CHECK(!moqctl_is_grease(0x9C));
  CHECK(!moqctl_is_grease(0x9E));
}

static void test_moqctl_unknown_error_normalizes_to_internal(void) {
  CHECK(
      moqctl_known_request_error(MOQCTL_ERR_NOT_SUPPORTED) ==
      MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(moqctl_known_request_error(0x7FFF) == MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(
      moqctl_known_publish_done(MOQCTL_DONE_TRACK_ENDED) ==
      MOQCTL_DONE_TRACK_ENDED);
  CHECK(moqctl_known_publish_done(0x7FFF) == MOQCTL_DONE_INTERNAL_ERROR);
}

/* ===== TEST: REQUEST_ERROR Redirect only with REDIRECT code ===== */

static void test_moqctl_request_error_redirect_roundtrip(void) {
  u8                   buf[64];
  usz                  off = 0;
  moqctl_request_error m   = {0};
  moqctl_request_error out;
  u8                   uri[3] = {'/', 'a', 'b'};
  wired_span           name   = wired_span_of((const u8*)"n", 1);

  m.error_code                 = MOQCTL_ERR_REDIRECT;
  m.retry_interval             = 0;
  m.reason                     = wired_span_of(0, 0);
  m.has_redirect               = 1;
  m.redirect.connect_uri       = wired_span_of(uri, 3);
  m.redirect.track_namespace.n = 0;
  m.redirect.track_name        = name;

  CHECK(moqctl_request_error_encode(wired_mspan_of(buf, sizeof buf), &off, &m));
  {
    usz roff = 0;
    CHECK(
        moqctl_request_error_take(wired_span_of(buf, off), &roff, &out) ==
        MOQCTL_OK);
    CHECK(roff == off);
  }
  CHECK(out.has_redirect);
  CHECK(out.redirect.connect_uri.n == 3);
  CHECK(out.redirect.track_name.n == 1);
}

/* ===== main ===== */

void test_moqctl(void) {
  test_moqctl_peek_type_setup();
  test_moqctl_peek_type_length_mismatch();
  test_moqctl_peek_type_truncated();
  test_moqctl_peek_type_unknown();
  test_moqctl_peek_type_known_unimplemented();
  test_moqctl_peek_type_max_len_field();

  test_moqctl_setup_roundtrip();
  test_moqctl_subscribe_roundtrip();
  test_moqctl_subscribe_ok_roundtrip();
  test_moqctl_publish_roundtrip();
  test_moqctl_request_ok_roundtrip();
  test_moqctl_request_error_roundtrip();
  test_moqctl_publish_done_roundtrip();
  test_moqctl_goaway_roundtrip();

  test_moqctl_goaway_uri_boundary();
  test_moqctl_reason_boundary();
  test_moqctl_location_roundtrip_and_order();

  test_moqctl_ftn_decode_basic();
  test_moqctl_ns_field_len_zero_rejected();
  test_moqctl_ns_fields_32_accept_33_reject();
  test_moqctl_ftn_4096_accept_4097_reject();
  test_moqctl_ftn_eq_exact_bytes();

  test_moqctl_params_forward_roundtrip();
  test_moqctl_params_type_overflow_violation();
  test_moqctl_params_unknown_type_violation();
  test_moqctl_params_duplicate_type_violation();
  test_moqctl_params_scope_violation();
  test_moqctl_params_delivery_timeout_decode();

  test_moqctl_setup_unknown_option_ignored();
  test_moqctl_setup_path_option_decode();

  test_moqctl_locfilter_next_group_and_largest();
  test_moqctl_locfilter_abs_start_and_range_roundtrip();
  test_moqctl_locfilter_end_group_overflow_violation();
  test_moqctl_locfilter_unknown_type_violation();

  test_moqctl_grease_pattern();
  test_moqctl_unknown_error_normalizes_to_internal();

  test_moqctl_request_error_redirect_roundtrip();
}
