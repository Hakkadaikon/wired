#include "app/rawquic/rawq.h"

#include "app/http3/server/srvloop/dispatch.h"
#include "app/webtransport/errmap/errmap/errmap.h"
#include "test.h"
#include "tls/ext/salpn/negotiate.h"
#include "transport/packet/frame/frame/frame.h"

/* One rawq_route case: raw x stream id x leading bytes -> route. */
typedef struct {
  int             raw;
  u64             id;
  const char*     first;
  usz             first_len;
  rawq_route_kind want;
} rawq_test_route_case;

/* T-B1 (plan 7.2): on raw QUIC the id's direction bit alone decides
 * (RFC 9000 2.1), even for a leading WT signal 0x41 ({40 41}) or uni type
 * 0x54 ({40 54}); on WebTransport today's classification is unchanged
 * (draft-ietf-webtrans-http3-15 4.2), a truncated varint being no signal. */
static const rawq_test_route_case rawq_test_routes[] = {
    {1, 0, "", 0, RAWQ_ROUTE_RAW_BIDI},
    {1, 4, "\x40\x41\x00", 3, RAWQ_ROUTE_RAW_BIDI},
    {1, 8, "\x03", 1, RAWQ_ROUTE_RAW_BIDI},
    {1, 2, "", 0, RAWQ_ROUTE_RAW_UNI},
    {1, 6, "\x40\x54\x00", 3, RAWQ_ROUTE_RAW_UNI},
    {1, 10, "\x00", 1, RAWQ_ROUTE_RAW_UNI},
    {0, 0, "\x40\x41\x00", 3, RAWQ_ROUTE_WT_BIDI},
    {0, 4, "\x01\x00", 2, RAWQ_ROUTE_REQUEST_H3},
    {0, 8, "", 0, RAWQ_ROUTE_REQUEST_H3},
    {0, 12, "\x40", 1, RAWQ_ROUTE_REQUEST_H3},
    {0, 2, "\x40\x54\x00", 3, RAWQ_ROUTE_WT_UNI},
    {0, 6, "\x00", 1, RAWQ_ROUTE_H3_UNI},
    {0, 10, "\x02", 1, RAWQ_ROUTE_H3_UNI},
    {0, 14, "\x40", 1, RAWQ_ROUTE_H3_UNI},
};

static void test_rawq_route_table(void) {
  usz n = sizeof rawq_test_routes / sizeof rawq_test_routes[0];
  for (usz i = 0; i < n; i++) {
    const rawq_test_route_case* c = &rawq_test_routes[i];
    wired_span f = wired_span_of((const u8*)c->first, c->first_len);
    CHECK(rawq_route(c->raw, c->id, f) == c->want);
  }
}

/* T-B2: raw is the identity (draft-ietf-moq-transport-19 3.3.4); WT maps
 * into the WT_APPLICATION_ERROR range (draft-ietf-webtrans-http3-15 4.4):
 * 1 -> 0x52e4a40fa8db + 1 + 1/0x1e = 0x52e4a40fa8dc. */
static void test_rawq_reset_out(void) {
  static const u32 codes[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x12, 0x9d};
  for (usz i = 0; i < sizeof codes / sizeof codes[0]; i++) {
    CHECK(rawq_reset_code_out(1, codes[i]) == codes[i]);
    CHECK(
        rawq_reset_code_out(0, codes[i]) == wired_wterrmap_to_http3(codes[i]));
  }
  CHECK(rawq_reset_code_out(1, 0xffffffffu) == 0xffffffffu);
  CHECK(rawq_reset_code_out(0, 1) == 0x52e4a40fa8dcull);
}

/* T-B3: raw maps any u32 wire code verbatim and leaves a wider one
 * unmapped (*app untouched, draft-ietf-moq-transport-22 13); WT goes
 * through wired_wterrmap_from_http3. */
static void test_rawq_reset_in(void) {
  u32 app = 7;
  CHECK(rawq_reset_code_in(1, 0x12, &app) == 1 && app == 0x12);
  CHECK(rawq_reset_code_in(1, 0xffffffffull, &app) == 1);
  CHECK(app == 0xffffffffu);
  app = 7;
  CHECK(rawq_reset_code_in(1, 0x100000000ull, &app) == 0 && app == 7);
  CHECK(rawq_reset_code_in(0, 0x52e4a40fa8dcull, &app) == 1 && app == 1);
  app = 7;
  CHECK(rawq_reset_code_in(0, 0x12, &app) == 0 && app == 7);
}

/* T-B4: RFC 9000 2.1 uni ids (3 raw, 11 after H3 control+QPACK, RFC 9114
 * 6.2); datagram prefix 0 on raw, else the RFC 9297 2.1 qsid varint length
 * (RFC 9000 16: qsid 0 -> 1, 64 -> 2, 16384 -> 4 bytes). */
static void test_rawq_uni_and_dgram(void) {
  CHECK(rawq_uni_first_id(1) == RAWQ_UNI_FIRST_RAW);
  CHECK(rawq_uni_first_id(1) == 3);
  CHECK(rawq_uni_first_id(0) == RAWQ_UNI_FIRST_H3);
  CHECK(rawq_uni_first_id(0) == 11);
  CHECK(rawq_dgram_prefix_len(1, RAWQ_NO_CONNECT_ID) == 0);
  CHECK(rawq_dgram_prefix_len(1, 4 * 16384) == 0);
  CHECK(rawq_dgram_prefix_len(0, 0) == 1);
  CHECK(rawq_dgram_prefix_len(0, 4 * 64) == 2);
  CHECK(rawq_dgram_prefix_len(0, 4 * 16384) == 4);
}

/* Static: wired_server/wired_srvloop are too large for the test stack. */
static wired_server  rawq_test_srv;
static wired_srvloop rawq_test_loop;

/* Feed one plaintext 1-RTT payload of two STREAM frames (uni id 2 "6f 00 01",
 * bidi id 0 "03 01 02" + FIN) through wired_srvloop_dispatch on a server whose
 * negotiated ALPN is alpn. */
static int rawq_test_dispatch(u8 alpn, int* got) {
  static const u8      uni[]  = {0x6f, 0x00, 0x01};
  static const u8      bidi[] = {0x03, 0x01, 0x02};
  u8                   pl[64];
  usz                  n;
  stream_frame         su  = {2, 0, sizeof uni, uni, 0};
  stream_frame         sb  = {0, 0, sizeof bidi, bidi, 1};
  wired_h3reqdrive_req req = {0};
  u8                   scratch[256], wrap[256];
  usz                  acc_len  = 0;
  u8                   acc_fin  = 0;
  int                  acc_done = 0;
  u8                   acc_buf[256];
  wired_srvloop_reqacc acc = {
      acc_buf, sizeof acc_buf, &acc_len, &acc_fin, &acc_done};
  wired_srvloop_dispatch_in in;
  CHECK(wired_srvloop_init(&rawq_test_loop, (const u8*)"\1\2\3\4", 4) == 1);
  rawq_test_srv.sdrv.alpn = alpn;
  n                       = frame_put_stream(pl, sizeof pl, &su);
  n += frame_put_stream(pl + n, sizeof pl - n, &sb);
  in = (wired_srvloop_dispatch_in){
      wired_span_of(pl, n), wired_mspan_of(scratch, sizeof scratch),
      wired_mspan_of(wrap, sizeof wrap), got, &req};
  *got = 0;
  return wired_srvloop_dispatch(
      &(wired_srvloop_dispatch_ctx){
          &rawq_test_srv, &rawq_test_loop.h3, &acc, &rawq_test_loop},
      &in);
}

/* T-E3 (plan 7.5): on raw QUIC a client uni stream "6f 00 .." lands whole in
 * wt_uni_streams[] (no type strip) and a client bidi "03 .." (SUBSCRIBE)
 * whole in wt_streams[], neither reaching the H3 request/QPACK paths. */
static void test_rawq_srvloop_raw_routes(void) {
  int got = 0;
  int u, b;
  CHECK(rawq_test_dispatch(SALPN_RAW, &got) == 1);
  u = wired_srvloop_wt_uni_slot_find(&rawq_test_loop, 2);
  b = wired_srvloop_wt_slot_find(&rawq_test_loop, 0);
  CHECK(u >= 0 && b >= 0);
  if (u < 0 || b < 0) return;
  CHECK(rawq_test_loop.wt_uni_streams[u].type_len == 0);
  CHECK(rawq_test_loop.wt_uni_streams[u].sig_pending == 0);
  CHECK(rawq_test_loop.wt_uni_streams[u].buf[0] == 0x6f);
  CHECK(rawq_test_loop.wt_uni_streams[u].buf[1] == 0x00);
  CHECK(rawq_test_loop.wt_streams[b].sig_len == 0);
  CHECK(rawq_test_loop.wt_streams[b].sig_pending == 0);
  CHECK(rawq_test_loop.wt_streams[b].buf[0] == 0x03);
  CHECK(rawq_test_loop.wt_streams[b].fin == 1);
  CHECK(rawq_test_loop.wt_streams[b].fin_off == 3);
  CHECK(got == 0);
  CHECK(rawq_test_loop.streams[0].in_use == 0);
}

/* T-E3 regression: the same bytes on h3 keep today's split -- bidi id 0 is a
 * request stream, uni "6f" is an unknown H3 type, neither is WT. */
static void test_rawq_srvloop_h3_unchanged(void) {
  int got = 0;
  rawq_test_dispatch(SALPN_H3, &got);
  CHECK(wired_srvloop_wt_uni_slot_find(&rawq_test_loop, 2) < 0);
  CHECK(wired_srvloop_wt_slot_find(&rawq_test_loop, 0) < 0);
  CHECK(rawq_test_loop.streams[0].in_use == 1);
}

void test_rawq(void) {
  test_rawq_route_table();
  test_rawq_reset_out();
  test_rawq_reset_in();
  test_rawq_uni_and_dgram();
  test_rawq_srvloop_raw_routes();
  test_rawq_srvloop_h3_unchanged();
}
