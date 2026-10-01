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

/* A complete unknown or known-but-unimplemented message is still framed
 * by its Length: off skips the whole message so the caller can carry on
 * with the next one (draft-ietf-moq-transport-19 SS10). */
static void test_moqctl_peek_type_unknown_skips_whole_message(void) {
  const u8   in[] = {0x99, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0x03};
  usz        off  = 0;
  u64        type = 0;
  wired_span body = {0, 0};

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_UNKNOWN_TYPE);
  CHECK(off == 6);
  CHECK(type == 0x1901); /* 2-byte vi64 */
  CHECK(body.n == 2 && body.p == in + 4);
}

static void test_moqctl_peek_type_unimplemented_skips_whole_message(void) {
  const u8   in[] = {0x16, 0x00, 0x01, 0x07, 0x03};
  usz        off  = 0;
  u64        type = 0;
  wired_span body = {0, 0};

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
  CHECK(off == 4);
  CHECK(type == 0x16);
}

/* FETCH_OK (0x18) is in the SS10 table: known, not unknown. */
static void test_moqctl_peek_type_fetch_ok_is_known(void) {
  const u8   in[] = {0x18, 0x00, 0x00};
  usz        off  = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(in, sizeof in), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
}

/* An unknown message whose body is cut short, or whose Length (up to the
 * 16-bit maximum) runs past the bytes available, waits for more bytes
 * exactly like a known one: INSUFFICIENT, off untouched. */
static void test_moqctl_peek_type_unknown_truncated_waits(void) {
  const u8   cut[]  = {0x99, 0x01, 0x00, 0x05, 0xAA, 0xBB};
  const u8   huge[] = {0x99, 0x01, 0xFF, 0xFF, 0xAA};
  usz        off    = 0;
  u64        type;
  wired_span body;

  CHECK(
      moqctl_peek_type(wired_span_of(cut, sizeof cut), &off, &type, &body) ==
      MOQCTL_INSUFFICIENT);
  CHECK(off == 0);
  CHECK(
      moqctl_peek_type(wired_span_of(huge, sizeof huge), &off, &type, &body) ==
      MOQCTL_INSUFFICIENT);
  CHECK(off == 0);
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
            wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
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
            wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
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
            wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
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
            wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
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
            wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE_OK, &out) ==
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
            wired_span_of(buf, off), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
        MOQCTL_OK);
  }
  CHECK(out.n == 1);
  CHECK(out.items[0].vi == 0);
}

/* Builds one Message Parameter list: count 1, Type 0x03 (AUTHORIZATION
 * TOKEN, draft SS10.2.2), Length-prefixed Token bytes `tok`. */
static usz moqctl_test_auth_param(u8* buf, usz cap, const u8* tok, usz n) {
  usz off = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, 1));
  CHECK(moqvi_put(
      wired_mspan_of(buf, cap), &off, MOQCTL_PARAM_AUTHORIZATION_TOKEN));
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, n));
  for (usz i = 0; i < n; i++) buf[off + i] = tok[i];
  return off + n;
}

/* draft SS10.2.2 AUTHORIZATION TOKEN (Type 0x03) with Alias Type USE_VALUE
 * decodes inside SUBSCRIBE: Token Type 0x01, Token Value "ab". Pinned wire
 * bytes: [03 (USE_VALUE), 01 (Token Type), 61 62]. */
static void test_moqctl_params_auth_token_use_value_decode(void) {
  static const u8 tok[] = {0x03, 0x01, 0x61, 0x62};
  u8              buf[16];
  usz             n = moqctl_test_auth_param(buf, sizeof buf, tok, sizeof tok);
  moqctl_params   out;
  usz             roff = 0;
  CHECK(
      moqctl_params_take(
          wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
      MOQCTL_OK);
  CHECK(out.n == 1);
  CHECK(out.items[0].type == MOQCTL_PARAM_AUTHORIZATION_TOKEN);
  CHECK(out.items[0].enc == MOQCTL_PENC_TOKEN);
  CHECK(out.items[0].token.alias_type == MOQCTL_TOKEN_USE_VALUE);
  CHECK(out.items[0].token.token_type == 1);
  wired_span v = out.items[0].token.value;
  CHECK(v.n == 2 && v.p[0] == 0x61 && v.p[1] == 0x62);
  CHECK(roff == n);
}

/* REGISTER carries Alias + Type + Value; DELETE/USE_ALIAS carry only the
 * Alias (SS10.2.2 Figure 5). Both PUBLISH and SUBSCRIBE may carry it. */
static void test_moqctl_params_auth_token_alias_shapes_decode(void) {
  static const u8 reg[] = {0x01, 0x07, 0x01, 0x78};
  static const u8 use[] = {0x02, 0x07};
  u8              buf[16];
  moqctl_params   out;
  usz             n = moqctl_test_auth_param(buf, sizeof buf, reg, sizeof reg);
  usz             roff = 0;
  CHECK(
      moqctl_params_take(
          wired_span_of(buf, n), &roff, MOQCTL_PCTX_PUBLISH, &out) ==
      MOQCTL_OK);
  CHECK(out.items[0].token.alias_type == MOQCTL_TOKEN_REGISTER);
  CHECK(out.items[0].token.alias == 7);
  CHECK(out.items[0].token.token_type == 1);
  CHECK(out.items[0].token.value.n == 1);
  n    = moqctl_test_auth_param(buf, sizeof buf, use, sizeof use);
  roff = 0;
  CHECK(
      moqctl_params_take(
          wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
      MOQCTL_OK);
  CHECK(out.items[0].token.alias_type == MOQCTL_TOKEN_USE_ALIAS);
  CHECK(out.items[0].token.alias == 7);
}

/* An undecodable Token structure is KEY_VALUE_FORMATTING_ERROR
 * (SS10.2.2): unknown Alias Type, USE_VALUE truncated before Token Type,
 * and DELETE with bytes trailing the Alias. */
static void test_moqctl_params_auth_token_malformed_kvfmt(void) {
  static const u8 bad_alias_type[] = {0x04, 0x01};
  static const u8 truncated[]      = {0x03};
  static const u8 trailing[]       = {0x00, 0x07, 0xFF};
  const u8*       cases[3]         = {bad_alias_type, truncated, trailing};
  const usz       lens[3]          = {2, 1, 3};
  for (usz i = 0; i < 3; i++) {
    u8            buf[16];
    moqctl_params out;
    usz n    = moqctl_test_auth_param(buf, sizeof buf, cases[i], lens[i]);
    usz roff = 0;
    CHECK(
        moqctl_params_take(
            wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE, &out) ==
        MOQCTL_PARAMS_KVFMT);
  }
}

/* AUTHORIZATION TOKEN outside its scope (SUBSCRIBE_OK) -> VIOLATION
 * (SS10.2.1). */
static void test_moqctl_params_auth_token_scope_violation(void) {
  static const u8 tok[] = {0x03, 0x01, 0x61};
  u8              buf[16];
  usz             n = moqctl_test_auth_param(buf, sizeof buf, tok, sizeof tok);
  moqctl_params   out;
  usz             roff = 0;
  CHECK(
      moqctl_params_take(
          wired_span_of(buf, n), &roff, MOQCTL_PCTX_SUBSCRIBE_OK, &out) ==
      MOQCTL_VIOLATION);
}

/* draft-ietf-moq-transport-19 10.2.x / 15.7 Table 13: each Message
 * Parameter Type, a well-formed Value, and the MOQCTL_PCTX_* set whose
 * "MAY appear in" sentence names it (plus SUBSCRIBE_TRACKS where 10.19.1
 * extends every SUBSCRIBE parameter to it). Copied from the draft, not
 * from moqctl.c, so the test is an independent oracle. */
typedef struct {
  u64       type;
  u32       ctx;
  const u8* val;
  usz       n;
} mqpt_row;

static const u8 MQPT_VARINT[]  = {0x05};
static const u8 MQPT_UINT8[]   = {0x01};
static const u8 MQPT_TOKEN[]   = {0x02, 0x02, 0x07}; /* USE_ALIAS 7 */
static const u8 MQPT_LOC[]     = {0x07, 0x03};
static const u8 MQPT_RANGE[]   = {0x02, 0x00, 0x03}; /* SetID 0, Start 3 */
static const u8 MQPT_PROPRNG[] = {0x03, 0x00, 0x02, 0x03};
static const u8 MQPT_LOCFLT[]  = {0x01, 0x01};       /* Next Group Start */
static const u8 MQPT_NS[]      = {0x01, 0x01, 0x61}; /* namespace ("a") */

static const mqpt_row MQPT_REGISTRY[] = {
    {0x02, 0x7D009, MQPT_VARINT, 1},  {0x03, 0x7D555, MQPT_TOKEN, 3},
    {0x04, 0x1001, MQPT_VARINT, 1},   {0x06, 0x7D009, MQPT_VARINT, 1},
    {0x08, 0x82A0E, MQPT_VARINT, 1},  {0x09, 0x80086, MQPT_LOC, 2},
    {0x0A, 0x10, MQPT_VARINT, 1},     {0x10, 0x500D, MQPT_UINT8, 1},
    {0x20, 0xD019, MQPT_UINT8, 1},    {0x22, 0x1011, MQPT_UINT8, 1},
    {0x25, 0x5019, MQPT_RANGE, 3},    {0x26, 0x5019, MQPT_RANGE, 3},
    {0x27, 0x5019, MQPT_RANGE, 3},    {0x28, 0x5019, MQPT_PROPRNG, 4},
    {0x29, 0x21000, MQPT_PROPRNG, 4}, {0x32, 0x5009, MQPT_VARINT, 1},
    {0x21, 0x5009, MQPT_LOCFLT, 2},   {0x34, 0x30000, MQPT_NS, 3},
};
#define MQPT_REGISTRY_N (sizeof MQPT_REGISTRY / sizeof MQPT_REGISTRY[0])

/* count 1 + Type + r's Value; returns the list length. */
static usz mqpt_build(u8* buf, usz cap, const mqpt_row* r) {
  usz off = 0;
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, 1));
  CHECK(moqvi_put(wired_mspan_of(buf, cap), &off, r->type));
  for (usz i = 0; i < r->n; i++) buf[off + i] = r->val[i];
  return off + r->n;
}

/* One parameter decoded under one context bit: accepted (and consumed
 * whole) exactly when the registry lists that context, else
 * PROTOCOL_VIOLATION (10.2.1). */
static void mqpt_check_one(const mqpt_row* r, u32 bit) {
  static moqctl_params out;
  u8                   buf[16];
  usz                  n    = mqpt_build(buf, sizeof buf, r);
  usz                  roff = 0;
  int got = moqctl_params_take(wired_span_of(buf, n), &roff, bit, &out);
  CHECK(got == ((r->ctx & bit) ? MOQCTL_OK : MOQCTL_VIOLATION));
  CHECK(got != MOQCTL_OK || (roff == n && out.items[0].type == r->type));
}

static void test_moqctl_params_registry_scope(void) {
  for (usz i = 0; i < MQPT_REGISTRY_N; i++)
    for (u32 b = 0; b < 20; b++) mqpt_check_one(&MQPT_REGISTRY[i], 1u << b);
}

/* Decodes the one-parameter list {type, val} under ctx into *out. */
static int mqpt_take(
    u64 type, const u8* val, usz n, u32 ctx, moqctl_params* out) {
  mqpt_row r = {type, 0, val, n};
  u8       buf[32];
  usz      len  = mqpt_build(buf, sizeof buf, &r);
  usz      roff = 0;
  return moqctl_params_take(wired_span_of(buf, len), &roff, ctx, out);
}

/* LOCATION_FILTER (10.2.9) is a Length-prefixed Location Filter (5.1.2):
 * AbsoluteRange {5,0} + End Group Delta 3 decodes into .lf and encodes
 * back to the same bytes. */
static void test_moqctl_params_location_filter_roundtrip(void) {
  static const u8      val[] = {0x04, 0x04, 0x05, 0x00, 0x03};
  static moqctl_params out;
  u8                   buf[32];
  usz                  off = 0;
  CHECK(
      mqpt_take(
          MOQCTL_PARAM_LOCATION_FILTER, val, sizeof val, MOQCTL_PCTX_SUBSCRIBE,
          &out) == MOQCTL_OK);
  CHECK(out.items[0].lf.type == MOQCTL_FILTER_ABS_RANGE);
  CHECK(out.items[0].lf.start.group == 5 && out.items[0].lf.start.object == 0);
  CHECK(out.items[0].lf.end_group_delta == 3);
  CHECK(moqctl_params_put(wired_mspan_of(buf, sizeof buf), &off, &out));
  CHECK(off == 2 + sizeof val);
  for (usz i = 0; i < sizeof val; i++) CHECK(buf[2 + i] == val[i]);
}

/* A Location Filter that is not exactly its Length: unknown Filter Type
 * (5.1.2), a trailing byte, or a filter cut short inside the Length. */
static void test_moqctl_params_location_filter_malformed(void) {
  static const u8      bad_type[] = {0x01, 0x05};
  static const u8      trailing[] = {0x02, 0x01, 0x00};
  static const u8      short_[]   = {0x02, 0x04, 0x05};
  static moqctl_params out;
  const u8*            cases[3] = {bad_type, trailing, short_};
  for (usz i = 0; i < 3; i++)
    CHECK(
        mqpt_take(
            MOQCTL_PARAM_LOCATION_FILTER, cases[i], 1 + cases[i][0],
            MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_VIOLATION);
}

/* TRACK_NAMESPACE_PREFIX (10.2.19) is a bare Track Namespace (2.4.1):
 * .bytes spans its encoding; a zero-length field is a VIOLATION. */
static void test_moqctl_params_namespace_prefix(void) {
  static const u8      ok[]  = {0x02, 0x01, 0x61, 0x02, 0x62, 0x63};
  static const u8      bad[] = {0x01, 0x00};
  static moqctl_params out;
  CHECK(
      mqpt_take(
          MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX, ok, sizeof ok,
          MOQCTL_PCTX_UPDATE_SUBSCRIBE_TRACKS, &out) == MOQCTL_OK);
  CHECK(out.items[0].bytes.n == sizeof ok && out.items[0].bytes.p[5] == 0x63);
  CHECK(
      mqpt_take(
          MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX, bad, sizeof bad,
          MOQCTL_PCTX_UPDATE_SUBSCRIBE_TRACKS, &out) == MOQCTL_VIOLATION);
}

/* uint8 value v of type under SUBSCRIBE: MOQCTL_OK or VIOLATION. */
static int mqpt_u8(u64 type, u8 v) {
  static moqctl_params out;
  return mqpt_take(type, &v, 1, MOQCTL_PCTX_SUBSCRIBE, &out);
}

/* FORWARD is 0 or 1 (10.2.17), GROUP_ORDER 1 or 2 (10.2.8); any other
 * value closes the session with PROTOCOL_VIOLATION. SUBSCRIBER_PRIORITY
 * takes the whole uint8. */
static void test_moqctl_params_uint8_value_ranges(void) {
  CHECK(mqpt_u8(MOQCTL_PARAM_FORWARD, 0) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_FORWARD, 1) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_FORWARD, 2) == MOQCTL_VIOLATION);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 0) == MOQCTL_VIOLATION);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 1) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 2) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_GROUP_ORDER, 3) == MOQCTL_VIOLATION);
  CHECK(mqpt_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 0) == MOQCTL_OK);
  CHECK(mqpt_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 255) == MOQCTL_OK);
}

/* The value range applies only to uint8-encoded rows: a varint row's
 * value is never range-rejected, even with a stray u8v. */
static void test_moqctl_param_range_uint8_only(void) {
  moqctl_param p = {0};
  p.u8v          = 5;
  CHECK(moqctl_param_in_range(
      moqctl_param_rule_for(MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT), &p));
  CHECK(
      !moqctl_param_in_range(moqctl_param_rule_for(MOQCTL_PARAM_FORWARD), &p));
}

/* The same Type twice (Type Delta 0), each with r's Value, under ctx. */
static int mqpt_twice(const mqpt_row* r, u32 ctx, moqctl_params* out) {
  u8  buf[32];
  usz n    = mqpt_build(buf, sizeof buf, r);
  usz off  = n;
  usz roff = 0;
  buf[0]   = 2; /* count */
  CHECK(moqvi_put(wired_mspan_of(buf, sizeof buf), &off, 0));
  for (usz i = 0; i < r->n; i++) buf[off + i] = r->val[i];
  return moqctl_params_take(wired_span_of(buf, off + r->n), &roff, ctx, out);
}

/* Range Filters MAY repeat (5.1.3); any other Type repeated is a
 * PROTOCOL_VIOLATION (10.2). */
static void test_moqctl_params_repeatable_filters(void) {
  static moqctl_params out;
  const mqpt_row sub_flt = {MOQCTL_PARAM_SUBGROUP_FILTER, 0, MQPT_RANGE, 3};
  const mqpt_row trk_flt = {
      MOQCTL_PARAM_TRACK_PROPERTY_FILTER, 0, MQPT_PROPRNG, 4};
  const mqpt_row order = {MOQCTL_PARAM_GROUP_ORDER, 0, MQPT_UINT8, 1};
  CHECK(mqpt_twice(&sub_flt, MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_OK);
  CHECK(out.n == 2 && out.items[1].type == MOQCTL_PARAM_SUBGROUP_FILTER);
  CHECK(mqpt_twice(&trk_flt, MOQCTL_PCTX_SUBSCRIBE_TRACKS, &out) == MOQCTL_OK);
  CHECK(mqpt_twice(&order, MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_VIOLATION);
}

/* REQUEST_OK (10.5) carries the parameters of whichever OK it stands for
 * (PUBLISH_OK, TRACK_STATUS_OK, ...): SUBSCRIBER_PRIORITY (PUBLISH_OK) and
 * LARGEST_OBJECT (TRACK_STATUS_OK) decode; GROUP_ORDER, legal in no OK,
 * is a PROTOCOL_VIOLATION. */
static void test_moqctl_request_ok_params_scope(void) {
  static const u8          prio[]  = {0x01, 0x20, 0x07};
  static const u8          large[] = {0x01, 0x09, 0x07, 0x03};
  static const u8          order[] = {0x01, 0x22, 0x01};
  static moqctl_request_ok m;
  usz                      off = 0;
  CHECK(
      moqctl_request_ok_take(wired_span_of(prio, sizeof prio), &off, &m) ==
      MOQCTL_OK);
  CHECK(m.params.n == 1 && m.params.items[0].u8v == 7);
  off = 0;
  CHECK(
      moqctl_request_ok_take(wired_span_of(large, sizeof large), &off, &m) ==
      MOQCTL_OK);
  CHECK(m.params.items[0].loc.group == 7 && m.params.items[0].loc.object == 3);
  off = 0;
  CHECK(
      moqctl_request_ok_take(wired_span_of(order, sizeof order), &off, &m) ==
      MOQCTL_VIOLATION);
}

/* moqctl_params_find: the first item of a Type, or 0 when absent -- so a
 * caller tells "absent" (use the draft default) from a decoded 0. */
static void test_moqctl_params_find(void) {
  static moqctl_params out;
  const mqpt_row       flt = {MOQCTL_PARAM_SUBGROUP_FILTER, 0, MQPT_RANGE, 3};
  CHECK(mqpt_twice(&flt, MOQCTL_PCTX_SUBSCRIBE, &out) == MOQCTL_OK);
  CHECK(
      moqctl_params_find(&out, MOQCTL_PARAM_SUBGROUP_FILTER) == &out.items[0]);
  CHECK(moqctl_params_find(&out, MOQCTL_PARAM_FORWARD) == 0);
}

/* Body of golden control message g (its envelope already checked). */
static wired_span mqpt_golden_body(const u8* g, usz n) {
  usz        off = 0;
  u64        type;
  wired_span body = {0, 0};
  CHECK(moqctl_peek_type(wired_span_of(g, n), &off, &type, &body) == MOQCTL_OK);
  return body;
}

/* Re-encodes m as golden g's type and checks it reproduces g exactly. */
static void mqpt_golden_reencode(
    const u8* g, usz n, u64 type, moqctl_encode_body_fn fn, const void* m) {
  u8  out[64];
  usz len = 0;
  moqctl_reencode(out, sizeof out, type, fn, m, &len);
  CHECK(len == n);
  for (usz i = 0; i < len; i++) CHECK(out[i] == g[i]);
}

/* Golden subscribe_params: FORWARD 1, SUBSCRIBER_PRIORITY 64,
 * LOCATION_FILTER AbsoluteRange {5,0}+3, GROUP_ORDER 2. */
static void test_moqctl_golden_subscribe_params(void) {
  static moqctl_subscribe m;
  wired_span              body = mqpt_golden_body(
      g_moqt_ctl_subscribe_params, G_MOQT_CTL_SUBSCRIBE_PARAMS_LEN);
  usz boff = 0;
  CHECK(moqctl_subscribe_take(body, &boff, &m) == MOQCTL_OK);
  CHECK(m.params.n == 4);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_FORWARD)->u8v == 1);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_SUBSCRIBER_PRIORITY)->u8v ==
      64);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_LOCATION_FILTER)
          ->lf.end_group_delta == 3);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_GROUP_ORDER)->u8v == 2);
  mqpt_golden_reencode(
      g_moqt_ctl_subscribe_params, G_MOQT_CTL_SUBSCRIBE_PARAMS_LEN,
      MOQCTL_T_SUBSCRIBE, moqctl_encode_subscribe, &m);
}

/* Golden subscribe_ok_params: EXPIRES 100, LARGEST_OBJECT {7,3}. */
static void test_moqctl_golden_subscribe_ok_params(void) {
  static moqctl_subscribe_ok m;
  wired_span                 body = mqpt_golden_body(
      g_moqt_ctl_subscribe_ok_params, G_MOQT_CTL_SUBSCRIBE_OK_PARAMS_LEN);
  usz boff = 0;
  CHECK(moqctl_subscribe_ok_take(body, &boff, &m) == MOQCTL_OK);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_EXPIRES)->vi == 100);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_LARGEST_OBJECT)->loc.object ==
      3);
  mqpt_golden_reencode(
      g_moqt_ctl_subscribe_ok_params, G_MOQT_CTL_SUBSCRIBE_OK_PARAMS_LEN,
      MOQCTL_T_SUBSCRIBE_OK, moqctl_encode_subscribe_ok, &m);
}

/* Golden request_ok_params (a PUBLISH_OK): FORWARD 0,
 * SUBSCRIBER_PRIORITY 7. */
static void test_moqctl_golden_request_ok_params(void) {
  static moqctl_request_ok m;
  wired_span               body = mqpt_golden_body(
      g_moqt_ctl_request_ok_params, G_MOQT_CTL_REQUEST_OK_PARAMS_LEN);
  usz boff = 0;
  CHECK(moqctl_request_ok_take(body, &boff, &m) == MOQCTL_OK);
  CHECK(moqctl_params_find(&m.params, MOQCTL_PARAM_FORWARD)->u8v == 0);
  CHECK(
      moqctl_params_find(&m.params, MOQCTL_PARAM_SUBSCRIBER_PRIORITY)->u8v ==
      7);
  mqpt_golden_reencode(
      g_moqt_ctl_request_ok_params, G_MOQT_CTL_REQUEST_OK_PARAMS_LEN,
      MOQCTL_T_REQUEST_OK, moqctl_encode_request_ok, &m);
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
  test_moqctl_peek_type_unknown_skips_whole_message();
  test_moqctl_peek_type_unimplemented_skips_whole_message();
  test_moqctl_peek_type_fetch_ok_is_known();
  test_moqctl_peek_type_unknown_truncated_waits();
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
  test_moqctl_params_auth_token_use_value_decode();
  test_moqctl_params_auth_token_alias_shapes_decode();
  test_moqctl_params_auth_token_malformed_kvfmt();
  test_moqctl_params_auth_token_scope_violation();
  test_moqctl_params_registry_scope();
  test_moqctl_params_location_filter_roundtrip();
  test_moqctl_params_location_filter_malformed();
  test_moqctl_params_namespace_prefix();
  test_moqctl_params_uint8_value_ranges();
  test_moqctl_param_range_uint8_only();
  test_moqctl_params_repeatable_filters();
  test_moqctl_request_ok_params_scope();
  test_moqctl_params_find();
  test_moqctl_golden_subscribe_params();
  test_moqctl_golden_subscribe_ok_params();
  test_moqctl_golden_request_ok_params();

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
