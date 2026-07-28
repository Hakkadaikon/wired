#include "app/moqt/ctl/moqctl.h"

#include "moqt_golden.h"
#include "test.h"

/* @file
 * draft-ietf-moq-transport-19 SS10 Control Message codec tests. Golden byte
 * sequences are pinned in tests/app/moqt_golden.h (generated from
 * examples/moqt_chat/testvectors/moqt_golden.json); this file never hand-
 * types a wire byte sequence for round-trip coverage.
 *
 * Ledger cross-reference (reported, not embedded in test names): common
 * envelope T-018/T-019/T-020/T-021/T-022/T-023, per-message round trips
 * T-024/T-032/T-039/T-041/T-043/T-048/T-049/T-050/T-051, Message Parameters
 * T-025..T-031, Setup Options T-033..T-037, GOAWAY T-040, REQUEST_OK T-042,
 * REQUEST_ERROR T-044/T-045/T-046/T-047, FORWARD T-052, Reason Phrase
 * T-053/T-054, Location T-055/T-056, Track Namespace/Name T-057..T-061,
 * Location Filter T-062..T-064, grease/unknown-code T-065..T-067.
 */

/* ===== TEST 1: common envelope round-trip (T-018/T-024) ===== */

static void test_moqctl_peek_type_setup(void) {
  usz       off = 0;
  u64       type;
  quic_span body;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(g_moqt_ctl_setup_impl, G_MOQT_CTL_SETUP_IMPL_LEN), &off,
          &type, &body) == QUIC_MOQCTL_OK);
  CHECK(type == G_MOQT_CTL_SETUP_IMPL_TYPE);
  CHECK(body.n == G_MOQT_CTL_SETUP_IMPL_MSG_LEN);
  CHECK(off == G_MOQT_CTL_SETUP_IMPL_LEN);
}

/* TEST 2: Message Length / Body mismatch -> VIOLATION (T-020). Shrink the
 * declared Length by 1 without touching the body bytes. */
static void test_moqctl_peek_type_length_mismatch(void) {
  u8        buf[32];
  usz       off = 0;
  u64       type;
  quic_span body;

  for (usz i = 0; i < G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN; i++)
    buf[i] = g_moqt_ctl_subscribe_ok_basic[i];
  buf[2] = G_MOQT_CTL_SUBSCRIBE_OK_BASIC_MSG_LEN + 1; /* claim one more byte
                                                          than actually
                                                          present */
  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(buf, G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN), &off, &type,
          &body) == QUIC_MOQCTL_INSUFFICIENT);
}

/* TEST 3: body cut short mid-message -> INSUFFICIENT (T-021). */
static void test_moqctl_peek_type_truncated(void) {
  usz       off = 0;
  u64       type;
  quic_span body;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(
              g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN - 3),
          &off, &type, &body) == QUIC_MOQCTL_INSUFFICIENT);
}

/* TEST 4: unknown message type -> UNKNOWN_TYPE (T-022). Type 0x2 (REQUEST_
 * UPDATE) is known-but-unimplemented; 0x99 is not in the SS10 table at
 * all. */
static void test_moqctl_peek_type_unknown(void) {
  const u8  in[] = {0x99, 0x01, 0x00, 0x00};
  usz       off  = 0;
  u64       type;
  quic_span body;

  CHECK(
      quic_moqctl_peek_type(quic_span_of(in, sizeof in), &off, &type, &body) ==
      QUIC_MOQCTL_UNKNOWN_TYPE);
}

/* TEST 5: known-but-unimplemented message type is distinguished from an
 * unknown one (T-019, T-022). REQUEST_UPDATE = 0x2, zero-length body. */
static void test_moqctl_peek_type_known_unimplemented(void) {
  const u8  in[] = {0x02, 0x00, 0x00};
  usz       off  = 0;
  u64       type;
  quic_span body;

  CHECK(
      quic_moqctl_peek_type(quic_span_of(in, sizeof in), &off, &type, &body) ==
      QUIC_MOQCTL_KNOWN_UNIMPLEMENTED);
}

/* TEST 6: message total length boundary at 2^16-1 (T-023). A Length field
 * that itself claims the max is accepted by peek_type as long as the body
 * bytes are actually present; this test only exercises the encoding of
 * the boundary value in the Length field via a minimal SUBSCRIBE_OK. */
static void test_moqctl_peek_type_max_len_field(void) {
  u8        buf[8];
  usz       off = 0;
  u64       type;
  quic_span body;

  buf[0] = 0x04; /* SUBSCRIBE_OK */
  buf[1] = 0xFF;
  buf[2] = 0xFF; /* Length = 65535, but only 2 bytes follow: insufficient */
  CHECK(
      quic_moqctl_peek_type(quic_span_of(buf, 3), &off, &type, &body) ==
      QUIC_MOQCTL_INSUFFICIENT);
}

/* ===== TEST 7-14: per-message round trip against golden (T-024) ===== */

static void test_moqctl_setup_roundtrip(void) {
  usz               off = 0;
  u64               type;
  quic_span         body;
  quic_moqctl_setup s;
  u8                out[G_MOQT_CTL_SETUP_IMPL_LEN];
  quic_mspan        ob   = quic_mspan_of(out, sizeof out);
  usz               eoff = 0;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(g_moqt_ctl_setup_impl, G_MOQT_CTL_SETUP_IMPL_LEN), &off,
          &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_setup_take(body, &boff, &s) == QUIC_MOQCTL_OK);
    CHECK(boff == body.n);
  }
  CHECK(!s.has_path);
  CHECK(!s.has_authority);
  CHECK(s.has_implementation);
  CHECK(s.implementation.n == 7);
  CHECK(s.implementation.p[0] == 'w');

  CHECK(quic_moqvi_put(ob, &eoff, type));
  {
    usz        len_at = eoff;
    usz        body_at;
    quic_mspan full = quic_mspan_of(out, sizeof out);
    eoff += 2; /* placeholder for Length */
    body_at = eoff;
    CHECK(quic_moqctl_setup_encode(full, &eoff, &s));
    out[len_at]     = (u8)((eoff - body_at) >> 8);
    out[len_at + 1] = (u8)(eoff - body_at);
  }
  CHECK(eoff == G_MOQT_CTL_SETUP_IMPL_LEN);
  for (usz i = 0; i < eoff; i++) CHECK(out[i] == g_moqt_ctl_setup_impl[i]);
}

/* Shared re-encode helper for the remaining messages: writes Type (vi64) +
 * placeholder Length + calls encode_body, then backpatches Length. */
typedef int (*moqctl_encode_body_fn)(quic_mspan, usz*, const void*);

static void moqctl_reencode(
    u8*                   out,
    usz                   cap,
    u64                   type,
    moqctl_encode_body_fn body_fn,
    const void*           msg,
    usz*                  out_len) {
  quic_mspan full = quic_mspan_of(out, cap);
  usz        eoff = 0;
  usz        len_at;
  usz        body_at;
  CHECK(quic_moqvi_put(full, &eoff, type));
  len_at = eoff;
  eoff += 2;
  body_at = eoff;
  CHECK(body_fn(full, &eoff, msg));
  out[len_at]     = (u8)((eoff - body_at) >> 8);
  out[len_at + 1] = (u8)(eoff - body_at);
  *out_len        = eoff;
}

static int moqctl_encode_subscribe(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_subscribe_encode(buf, off, m);
}

static void test_moqctl_subscribe_roundtrip(void) {
  usz                   off = 0;
  u64                   type;
  quic_span             body;
  quic_moqctl_subscribe m;
  u8                    out[G_MOQT_CTL_SUBSCRIBE_BASIC_LEN];
  usz                   out_len;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(
              g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
          &off, &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_subscribe_take(body, &boff, &m) == QUIC_MOQCTL_OK);
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

static int moqctl_encode_subscribe_ok(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_subscribe_ok_encode(buf, off, m);
}

static void test_moqctl_subscribe_ok_roundtrip(void) {
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  quic_moqctl_subscribe_ok m;
  u8                       out[G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN];
  usz                      out_len;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(
              g_moqt_ctl_subscribe_ok_basic, G_MOQT_CTL_SUBSCRIBE_OK_BASIC_LEN),
          &off, &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_subscribe_ok_take(body, &boff, &m) == QUIC_MOQCTL_OK);
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

static int moqctl_encode_publish(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_publish_encode(buf, off, m);
}

static void test_moqctl_publish_roundtrip(void) {
  usz                 off = 0;
  u64                 type;
  quic_span           body;
  quic_moqctl_publish m;
  u8                  out[G_MOQT_CTL_PUBLISH_BASIC_LEN];
  usz                 out_len;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN),
          &off, &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_publish_take(body, &boff, &m) == QUIC_MOQCTL_OK);
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

static int moqctl_encode_request_ok(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_request_ok_encode(buf, off, m);
}

static void test_moqctl_request_ok_roundtrip(void) {
  usz                    off = 0;
  u64                    type;
  quic_span              body;
  quic_moqctl_request_ok m;
  u8                     out[G_MOQT_CTL_REQUEST_OK_BASIC_LEN];
  usz                    out_len;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(
              g_moqt_ctl_request_ok_basic, G_MOQT_CTL_REQUEST_OK_BASIC_LEN),
          &off, &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_request_ok_take(body, &boff, &m) == QUIC_MOQCTL_OK);
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
    quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_request_error_encode(buf, off, m);
}

static void test_moqctl_request_error_roundtrip(void) {
  usz                       off = 0;
  u64                       type;
  quic_span                 body;
  quic_moqctl_request_error m;
  u8                        out[G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN];
  usz                       out_len;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(
              g_moqt_ctl_request_error_not_supported,
              G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN),
          &off, &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_request_error_take(body, &boff, &m) == QUIC_MOQCTL_OK);
  }
  CHECK(m.error_code == QUIC_MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(m.retry_interval == 0);
  CHECK(m.reason.n == 13);
  CHECK(!m.has_redirect);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_request_error, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_REQUEST_ERROR_NOT_SUPPORTED_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_request_error_not_supported[i]);
}

static int moqctl_encode_publish_done(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_publish_done_encode(buf, off, m);
}

static void test_moqctl_publish_done_roundtrip(void) {
  usz                      off = 0;
  u64                      type;
  quic_span                body;
  quic_moqctl_publish_done m;
  u8                       out[G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN];
  usz                      out_len;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(
              g_moqt_ctl_publish_done_track_ended,
              G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN),
          &off, &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_publish_done_take(body, &boff, &m) == QUIC_MOQCTL_OK);
  }
  CHECK(m.status_code == QUIC_MOQCTL_DONE_TRACK_ENDED);
  CHECK(m.stream_count == 2);
  CHECK(m.reason.n == 0);

  moqctl_reencode(
      out, sizeof out, type, moqctl_encode_publish_done, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_PUBLISH_DONE_TRACK_ENDED_LEN);
  for (usz i = 0; i < out_len; i++)
    CHECK(out[i] == g_moqt_ctl_publish_done_track_ended[i]);
}

static int moqctl_encode_goaway(quic_mspan buf, usz* off, const void* m) {
  return quic_moqctl_goaway_encode(buf, off, m);
}

static void test_moqctl_goaway_roundtrip(void) {
  usz                off = 0;
  u64                type;
  quic_span          body;
  quic_moqctl_goaway m;
  u8                 out[G_MOQT_CTL_GOAWAY_EMPTY_LEN];
  usz                out_len;

  CHECK(
      quic_moqctl_peek_type(
          quic_span_of(g_moqt_ctl_goaway_empty, G_MOQT_CTL_GOAWAY_EMPTY_LEN),
          &off, &type, &body) == QUIC_MOQCTL_OK);
  {
    usz boff = 0;
    CHECK(quic_moqctl_goaway_take(body, &boff, &m) == QUIC_MOQCTL_OK);
  }
  CHECK(m.new_session_uri.n == 0);
  CHECK(m.timeout == 0);

  moqctl_reencode(out, sizeof out, type, moqctl_encode_goaway, &m, &out_len);
  CHECK(out_len == G_MOQT_CTL_GOAWAY_EMPTY_LEN);
  for (usz i = 0; i < out_len; i++) CHECK(out[i] == g_moqt_ctl_goaway_empty[i]);
}

/* ===== TEST: GOAWAY New Session URI 8192 boundary (T-040) ===== */

static void test_moqctl_goaway_uri_boundary(void) {
  u8                 buf_ok[3 + QUIC_MOQCTL_MAX_URI_LEN + 4];
  u8                 buf_reject[3 + QUIC_MOQCTL_MAX_URI_LEN + 5];
  usz                at;
  quic_moqctl_goaway m;

  /* 8192 accepted: len varint(2B, 0x9f 0x40 encodes 8192) + 8192 bytes +
   * timeout varint(1B, 0x00). moqvi_put proves the length encoding; we
   * only need decode acceptance here. */
  at = 0;
  CHECK(quic_moqvi_put(quic_mspan_of(buf_ok, sizeof buf_ok), &at, 8192));
  for (usz i = 0; i < QUIC_MOQCTL_MAX_URI_LEN; i++) buf_ok[at + i] = 'a';
  at += QUIC_MOQCTL_MAX_URI_LEN;
  CHECK(quic_moqvi_put(quic_mspan_of(buf_ok, sizeof buf_ok), &at, 0));
  {
    usz off = 0;
    CHECK(
        quic_moqctl_goaway_take(quic_span_of(buf_ok, at), &off, &m) ==
        QUIC_MOQCTL_OK);
    CHECK(m.new_session_uri.n == QUIC_MOQCTL_MAX_URI_LEN);
  }

  /* 8193 rejected */
  at = 0;
  CHECK(quic_moqvi_put(
      quic_mspan_of(buf_reject, sizeof buf_reject), &at,
      QUIC_MOQCTL_MAX_URI_LEN + 1));
  for (usz i = 0; i < QUIC_MOQCTL_MAX_URI_LEN + 1; i++)
    buf_reject[at + i] = 'a';
  at += QUIC_MOQCTL_MAX_URI_LEN + 1;
  {
    usz off = 0;
    CHECK(
        quic_moqctl_goaway_take(quic_span_of(buf_reject, at), &off, &m) ==
        QUIC_MOQCTL_VIOLATION);
  }
}

/* ===== TEST: Reason Phrase 1024 boundary (T-054) ===== */

static void test_moqctl_reason_boundary(void) {
  u8                 buf_ok[3 + QUIC_MOQCTL_MAX_REASON_LEN];
  u8                 buf_reject[3 + QUIC_MOQCTL_MAX_REASON_LEN + 1];
  usz                at;
  quic_moqctl_reason r;

  at = 0;
  CHECK(quic_moqvi_put(quic_mspan_of(buf_ok, sizeof buf_ok), &at, 1024));
  for (usz i = 0; i < 1024; i++) buf_ok[at + i] = 'x';
  at += 1024;
  {
    usz off = 0;
    CHECK(
        quic_moqctl_reason_take(quic_span_of(buf_ok, at), &off, &r) ==
        QUIC_MOQCTL_OK);
    CHECK(r.n == 1024);
  }

  at = 0;
  CHECK(
      quic_moqvi_put(quic_mspan_of(buf_reject, sizeof buf_reject), &at, 1025));
  for (usz i = 0; i < 1025; i++) buf_reject[at + i] = 'x';
  at += 1025;
  {
    usz off = 0;
    CHECK(
        quic_moqctl_reason_take(quic_span_of(buf_reject, at), &off, &r) ==
        QUIC_MOQCTL_VIOLATION);
  }
}

/* ===== TEST: Location encode/compare (T-055/T-056) ===== */

static void test_moqctl_location_roundtrip_and_order(void) {
  u8              buf[32];
  usz             off = 0;
  quic_moqctl_loc a   = {5, 10};
  quic_moqctl_loc b   = {5, 11};
  quic_moqctl_loc c   = {6, 0};
  quic_moqctl_loc out;

  CHECK(quic_moqctl_loc_put(quic_mspan_of(buf, sizeof buf), &off, a));
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_loc_take(quic_span_of(buf, off), &roff, &out) ==
        QUIC_MOQCTL_OK);
    CHECK(out.group == a.group);
    CHECK(out.object == a.object);
  }
  CHECK(quic_moqctl_loc_less(a, b));
  CHECK(quic_moqctl_loc_less(b, c));
  CHECK(!quic_moqctl_loc_less(b, a));
}

/* ===== TEST: Track Namespace / Full Track Name (T-057..T-061) ===== */

static void test_moqctl_ftn_decode_basic(void) {
  quic_moqctl_ftn f;
  usz             off = 0;

  CHECK(
      quic_moqctl_ftn_take(
          quic_span_of(
              g_moqt_name_full_track_name_basic,
              G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN),
          &off, &f) == QUIC_MOQCTL_OK);
  CHECK(off == G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN);
  CHECK(f.ns.n == 2);
  CHECK(f.ns.fields[0].n == 4);
  CHECK(f.ns.fields[1].n == 5);
  CHECK(f.name.n == 5);
}

/* T-058: Field Length 0 -> PROTOCOL_VIOLATION. */
static void test_moqctl_ns_field_len_zero_rejected(void) {
  quic_moqctl_ns ns;
  usz            off = 0;

  CHECK(
      quic_moqctl_ns_take(
          quic_span_of(
              g_moqt_name_ns_field_len_zero_reject,
              G_MOQT_NAME_NS_FIELD_LEN_ZERO_REJECT_LEN),
          &off, &ns) == QUIC_MOQCTL_VIOLATION);
}

/* T-059: 32 fields accepted, 33 rejected. */
static void test_moqctl_ns_fields_32_accept_33_reject(void) {
  quic_moqctl_ns ns;
  usz            off;

  off = 0;
  CHECK(
      quic_moqctl_ns_take(
          quic_span_of(
              g_moqt_name_ns_fields_32_accept,
              G_MOQT_NAME_NS_FIELDS_32_ACCEPT_LEN),
          &off, &ns) == QUIC_MOQCTL_OK);
  CHECK(ns.n == 32);

  off = 0;
  CHECK(
      quic_moqctl_ns_take(
          quic_span_of(
              g_moqt_name_ns_fields_33_reject,
              G_MOQT_NAME_NS_FIELDS_33_REJECT_LEN),
          &off, &ns) == QUIC_MOQCTL_VIOLATION);
}

/* T-060: Full Track Name 4096 boundary. */
static void test_moqctl_ftn_4096_accept_4097_reject(void) {
  quic_moqctl_ftn f;
  usz             off;

  off = 0;
  CHECK(
      quic_moqctl_ftn_take(
          quic_span_of(
              g_moqt_name_ftn_4096_accept, G_MOQT_NAME_FTN_4096_ACCEPT_LEN),
          &off, &f) == QUIC_MOQCTL_OK);

  off = 0;
  CHECK(
      quic_moqctl_ftn_take(
          quic_span_of(
              g_moqt_name_ftn_4097_reject, G_MOQT_NAME_FTN_4097_REJECT_LEN),
          &off, &f) == QUIC_MOQCTL_VIOLATION);
}

/* T-061: exact byte comparison, no encoding-dependent shortcuts. */
static void test_moqctl_ftn_eq_exact_bytes(void) {
  quic_moqctl_ftn a, b;
  usz             off;

  off = 0;
  CHECK(
      quic_moqctl_ftn_take(
          quic_span_of(
              g_moqt_name_full_track_name_basic,
              G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN),
          &off, &a) == QUIC_MOQCTL_OK);
  off = 0;
  CHECK(
      quic_moqctl_ftn_take(
          quic_span_of(
              g_moqt_name_full_track_name_basic,
              G_MOQT_NAME_FULL_TRACK_NAME_BASIC_LEN),
          &off, &b) == QUIC_MOQCTL_OK);
  CHECK(quic_moqctl_ftn_eq(&a, &b));
  b.name.p = (const u8*)"zzzzz";
  CHECK(!quic_moqctl_ftn_eq(&a, &b));
}

/* ===== TEST: Message Parameters (T-025..T-031) ===== */

/* T-025/T-026: FORWARD (uint8) round trip inside SUBSCRIBE's scope. */
static void test_moqctl_params_forward_roundtrip(void) {
  u8                 buf[16];
  usz                off = 0;
  quic_moqctl_params p   = {0};
  quic_moqctl_params out;

  p.items[0].type = QUIC_MOQCTL_PARAM_FORWARD;
  p.items[0].enc  = QUIC_MOQCTL_PENC_UINT8;
  p.items[0].u8v  = 0;
  p.n             = 1;

  CHECK(quic_moqctl_params_put(quic_mspan_of(buf, sizeof buf), &off, &p));
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_params_take(
            quic_span_of(buf, off), &roff, QUIC_MOQCTL_T_SUBSCRIBE, &out) ==
        QUIC_MOQCTL_OK);
  }
  CHECK(out.n == 1);
  CHECK(out.items[0].type == QUIC_MOQCTL_PARAM_FORWARD);
  CHECK(out.items[0].u8v == 0);
}

/* T-027: cumulative Parameter Type overflow -> VIOLATION. Two params whose
 * deltas sum past 2^64-1. */
static void test_moqctl_params_type_overflow_violation(void) {
  u8                 buf[24];
  usz                off = 0;
  quic_moqctl_params out;

  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 2)); /* count */
  CHECK(quic_moqvi_put(
      quic_mspan_of(buf, sizeof buf), &off, QUIC_MOQCTL_PARAM_FORWARD));
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 1)); /* value */
  CHECK(quic_moqvi_put(
      quic_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* delta
                                                           overflow */
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_params_take(
            quic_span_of(buf, off), &roff, QUIC_MOQCTL_T_SUBSCRIBE, &out) ==
        QUIC_MOQCTL_VIOLATION);
  }
}

/* T-028: unknown Message Parameter Type -> VIOLATION. */
static void test_moqctl_params_unknown_type_violation(void) {
  u8                 buf[8];
  usz                off = 0;
  quic_moqctl_params out;

  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 0x77));
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 0));
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_params_take(
            quic_span_of(buf, off), &roff, QUIC_MOQCTL_T_SUBSCRIBE, &out) ==
        QUIC_MOQCTL_VIOLATION);
  }
}

/* T-029: duplicate Parameter Type -> VIOLATION. */
static void test_moqctl_params_duplicate_type_violation(void) {
  u8                 buf[16];
  usz                off = 0;
  quic_moqctl_params out;

  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 2));
  CHECK(quic_moqvi_put(
      quic_mspan_of(buf, sizeof buf), &off, QUIC_MOQCTL_PARAM_FORWARD));
  buf[off] = 1;
  off += 1; /* uint8 value */
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 0)); /* delta 0
                                                                      -> same
                                                                      type */
  buf[off] = 1;
  off += 1;
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_params_take(
            quic_span_of(buf, off), &roff, QUIC_MOQCTL_T_SUBSCRIBE, &out) ==
        QUIC_MOQCTL_VIOLATION);
  }
}

/* T-031: known parameter type outside its allowed message scope ->
 * VIOLATION. FORWARD is legal in SUBSCRIBE/PUBLISH but not SUBSCRIBE_OK. */
static void test_moqctl_params_scope_violation(void) {
  u8                 buf[8];
  usz                off = 0;
  quic_moqctl_params out;

  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(quic_moqvi_put(
      quic_mspan_of(buf, sizeof buf), &off, QUIC_MOQCTL_PARAM_FORWARD));
  buf[off] = 1;
  off += 1;
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_params_take(
            quic_span_of(buf, off), &roff, QUIC_MOQCTL_T_SUBSCRIBE_OK, &out) ==
        QUIC_MOQCTL_VIOLATION);
  }
}

/* T-030: SUBGROUP/OBJECT_DELIVERY_TIMEOUT decode as varint, 0 = unset. */
static void test_moqctl_params_delivery_timeout_decode(void) {
  u8                 buf[16];
  usz                off = 0;
  quic_moqctl_params out;

  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 1));
  CHECK(quic_moqvi_put(
      quic_mspan_of(buf, sizeof buf), &off,
      QUIC_MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT));
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 0));
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_params_take(
            quic_span_of(buf, off), &roff, QUIC_MOQCTL_T_SUBSCRIBE, &out) ==
        QUIC_MOQCTL_OK);
  }
  CHECK(out.n == 1);
  CHECK(out.items[0].vi == 0);
}

/* ===== TEST: SETUP Setup Options behaviors (T-033..T-037) ===== */

/* T-033: unknown Setup Option (including a duplicate of it) is ignored. */
static void test_moqctl_setup_unknown_option_ignored(void) {
  u8                buf[16];
  usz               off = 0;
  quic_moqctl_setup s;

  /* two odd, unrecognized option types (0x0B, delta then +0x0A -> 0x15),
   * each carrying one raw byte -- both must be silently ignored. */
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 0x0B));
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 1));
  buf[off] = 0xAA;
  off += 1;
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 0x0A));
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 1));
  buf[off] = 0xBB;
  off += 1;

  {
    usz soff = 0;
    CHECK(
        quic_moqctl_setup_take(quic_span_of(buf, off), &soff, &s) ==
        QUIC_MOQCTL_OK);
  }
  CHECK(!s.has_path);
  CHECK(!s.has_authority);
  CHECK(!s.has_implementation);
}

/* T-037: MOQT_IMPLEMENTATION option decode (UTF-8 name+version). Already
 * covered end-to-end by test_moqctl_setup_roundtrip via the golden vector;
 * this test isolates the PATH option instead for independent coverage. */
static void test_moqctl_setup_path_option_decode(void) {
  u8                buf[16];
  usz               off = 0;
  quic_moqctl_setup s;

  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 1)); /* PATH=1 */
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 3));
  buf[off]     = '/';
  buf[off + 1] = 'a';
  buf[off + 2] = 'b';
  off += 3;

  {
    usz soff = 0;
    CHECK(
        quic_moqctl_setup_take(quic_span_of(buf, off), &soff, &s) ==
        QUIC_MOQCTL_OK);
  }
  CHECK(s.has_path);
  CHECK(s.path.n == 3);
  CHECK(s.path.p[0] == '/');
}

/* ===== TEST: Location Filter (T-062..T-064) ===== */

static void test_moqctl_locfilter_next_group_and_largest(void) {
  const u8              in_ng[] = {0x01};
  const u8              in_lg[] = {0x02};
  usz                   off;
  quic_moqctl_locfilter f;

  off = 0;
  CHECK(
      quic_moqctl_locfilter_take(quic_span_of(in_ng, sizeof in_ng), &off, &f) ==
      QUIC_MOQCTL_OK);
  CHECK(f.type == QUIC_MOQCTL_FILTER_NEXT_GROUP);
  CHECK(off == 1);

  off = 0;
  CHECK(
      quic_moqctl_locfilter_take(quic_span_of(in_lg, sizeof in_lg), &off, &f) ==
      QUIC_MOQCTL_OK);
  CHECK(f.type == QUIC_MOQCTL_FILTER_LARGEST);
}

static void test_moqctl_locfilter_abs_start_and_range_roundtrip(void) {
  u8                    buf[32];
  usz                   off  = 0;
  quic_moqctl_locfilter f_in = {0};
  quic_moqctl_locfilter f_out;

  f_in.type            = QUIC_MOQCTL_FILTER_ABS_RANGE;
  f_in.start.group     = 3;
  f_in.start.object    = 0;
  f_in.end_group_delta = 5;

  CHECK(quic_moqctl_locfilter_put(quic_mspan_of(buf, sizeof buf), &off, &f_in));
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_locfilter_take(quic_span_of(buf, off), &roff, &f_out) ==
        QUIC_MOQCTL_OK);
  }
  CHECK(f_out.type == QUIC_MOQCTL_FILTER_ABS_RANGE);
  CHECK(f_out.start.group == 3);
  CHECK(f_out.end_group_delta == 5);
}

/* T-063: End Group overflow (Start.Group + Delta > 2^64-1) -> VIOLATION. */
static void test_moqctl_locfilter_end_group_overflow_violation(void) {
  u8                    buf[24];
  usz                   off = 0;
  quic_moqctl_locfilter f;

  CHECK(quic_moqvi_put(
      quic_mspan_of(buf, sizeof buf), &off, QUIC_MOQCTL_FILTER_ABS_RANGE));
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 5)); /* Group */
  CHECK(quic_moqvi_put(quic_mspan_of(buf, sizeof buf), &off, 0)); /* Object */
  CHECK(quic_moqvi_put(
      quic_mspan_of(buf, sizeof buf), &off, (u64)-1)); /* delta
                                                           overflow */
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_locfilter_take(quic_span_of(buf, off), &roff, &f) ==
        QUIC_MOQCTL_VIOLATION);
  }
}

/* T-064: unknown Filter Type -> VIOLATION. */
static void test_moqctl_locfilter_unknown_type_violation(void) {
  const u8              in[] = {0x05};
  usz                   off  = 0;
  quic_moqctl_locfilter f;

  CHECK(
      quic_moqctl_locfilter_take(quic_span_of(in, sizeof in), &off, &f) ==
      QUIC_MOQCTL_VIOLATION);
}

/* ===== TEST: grease / unknown error code normalization (T-065..T-067) ===== */

static void test_moqctl_grease_pattern(void) {
  CHECK(quic_moqctl_is_grease(0x9D));
  CHECK(quic_moqctl_is_grease(0x9D + 0x7f));
  CHECK(quic_moqctl_is_grease(0x9D + 2 * 0x7f));
  CHECK(!quic_moqctl_is_grease(0));
  CHECK(!quic_moqctl_is_grease(0x9C));
  CHECK(!quic_moqctl_is_grease(0x9E));
}

static void test_moqctl_unknown_error_normalizes_to_internal(void) {
  CHECK(
      quic_moqctl_known_request_error(QUIC_MOQCTL_ERR_NOT_SUPPORTED) ==
      QUIC_MOQCTL_ERR_NOT_SUPPORTED);
  CHECK(
      quic_moqctl_known_request_error(0x7FFF) ==
      QUIC_MOQCTL_ERR_INTERNAL_ERROR);
  CHECK(
      quic_moqctl_known_publish_done(QUIC_MOQCTL_DONE_TRACK_ENDED) ==
      QUIC_MOQCTL_DONE_TRACK_ENDED);
  CHECK(
      quic_moqctl_known_publish_done(0x7FFF) ==
      QUIC_MOQCTL_DONE_INTERNAL_ERROR);
}

/* ===== TEST: REQUEST_ERROR Redirect only with REDIRECT code (T-044/T-045)
 * ===== */

static void test_moqctl_request_error_redirect_roundtrip(void) {
  u8                        buf[64];
  usz                       off = 0;
  quic_moqctl_request_error m   = {0};
  quic_moqctl_request_error out;
  u8                        uri[3] = {'/', 'a', 'b'};
  quic_span                 name   = quic_span_of((const u8*)"n", 1);

  m.error_code                 = QUIC_MOQCTL_ERR_REDIRECT;
  m.retry_interval             = 0;
  m.reason                     = quic_span_of(0, 0);
  m.has_redirect               = 1;
  m.redirect.connect_uri       = quic_span_of(uri, 3);
  m.redirect.track_namespace.n = 0;
  m.redirect.track_name        = name;

  CHECK(quic_moqctl_request_error_encode(
      quic_mspan_of(buf, sizeof buf), &off, &m));
  {
    usz roff = 0;
    CHECK(
        quic_moqctl_request_error_take(quic_span_of(buf, off), &roff, &out) ==
        QUIC_MOQCTL_OK);
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
