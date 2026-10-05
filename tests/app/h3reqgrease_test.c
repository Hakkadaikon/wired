#include "test.h"

/* RFC 9114 7.2.8 / 9: an unknown or reserved (GREASE, 0x1f*N+0x21) frame
 * MAY lead a request stream and MUST be ignored, so a WebTransport Extended
 * CONNECT (RFC 9220 3) behind one is still answered at its HEADERS frame.
 * RFC 9114 4.1: DATA before HEADERS stays H3_FRAME_UNEXPECTED. */

/* One direct-dispatch fixture (ctx->l == 0: the single-accumulator path). */
struct h3g_fix {
  wired_server         s;
  wired_h3srv_state    h3;
  u8                   buf[1024], wrap[1200], scratch[512];
  usz                  len;
  u8                   fin;
  int                  done, got;
  wired_h3reqdrive_req req;
};

/* moxygen's leading GREASE (type 0xfa = 0x1f*7+0x21, length 0) and the
 * second reserved type 0x138 (= 0x1f*9+0x21) as 2-byte varints. */
static const u8 h3g_grease_fa[]  = {0x40, 0xfa, 0x00};
static const u8 h3g_grease_138[] = {0x41, 0x38, 0x00};

/* Append a HEADERS frame carrying an Extended CONNECT to out at *n. */
static void h3g_put_connect(u8* out, usz cap, usz* n) {
  u8              fields[256];
  wired_obuf      fob = obuf_of(fields, sizeof fields);
  wired_obuf      hob = obuf_of(out + *n, cap - *n);
  h3req_pseudo_in pin = {
      wired_span_of((const u8*)"CONNECT", 7),
      wired_span_of((const u8*)"https", 5), wired_span_of((const u8*)"h", 1),
      wired_span_of((const u8*)"/", 1),
      wired_span_of((const u8*)"webtransport", 12)};
  CHECK(h3req_enc_pseudo(&pin, &fob) == 1);
  CHECK(
      h3_frame_put(&hob, H3_FRAME_HEADERS, wired_span_of(fields, fob.len)) !=
      0);
  *n += hob.len;
}

static void h3g_put(u8* out, usz* n, const u8* p, usz pn) {
  for (usz i = 0; i < pn; i++) out[(*n)++] = p[i];
}

/* Deliver h3[off, off+len) as one request STREAM frame (stream 0). */
static void h3g_deliver(
    struct h3g_fix* f, const u8* h3, usz off, usz len, int fin) {
  u8                   pl[1100];
  wired_obuf           ob  = obuf_of(pl, sizeof pl);
  stream_frame         sf  = {0, off, len, h3 + off, fin};
  wired_srvloop_reqacc acc = {
      f->buf, sizeof f->buf, &f->len, &f->fin, &f->done};
  wired_srvloop_dispatch_in in = {
      wired_span_of(pl, 0), wired_mspan_of(f->scratch, sizeof f->scratch),
      wired_mspan_of(f->wrap, sizeof f->wrap), &f->got, &f->req};
  CHECK(appdata_stream_frame(&sf, &ob) == 1);
  in.payload = wired_span_of(pl, ob.len);
  CHECK(
      wired_srvloop_dispatch(
          &(wired_srvloop_dispatch_ctx){&f->s, &f->h3, &acc, 0}, &in) == 1);
}

static int h3g_is_connect(const struct h3g_fix* f) {
  return f->got == 1 && f->req.method_len == 7 && f->req.method[0] == 'C';
}

/* GREASE (0xfa, len 0) then HEADERS, no FIN: CONNECT answered. */
static void test_h3reqgrease_then_connect(void) {
  static struct h3g_fix f;
  u8                    h3[512];
  usz                   n = 0;
  f                       = (struct h3g_fix){0};
  h3g_put(h3, &n, h3g_grease_fa, sizeof h3g_grease_fa);
  h3g_put_connect(h3, sizeof h3, &n);
  h3g_deliver(&f, h3, 0, n, 0);
  CHECK(h3g_is_connect(&f));
  CHECK(f.req.protocol_len == 12);
}

/* Two reserved frames (0xfa, 0x138 with a 2-byte payload) then HEADERS. */
static void test_h3reqgrease_two_frames(void) {
  static struct h3g_fix f;
  static const u8       g2[] = {0x41, 0x38, 0x02, 0xaa, 0xbb};
  u8                    h3[512];
  usz                   n = 0;
  f                       = (struct h3g_fix){0};
  h3g_put(h3, &n, h3g_grease_fa, sizeof h3g_grease_fa);
  h3g_put(h3, &n, g2, sizeof g2);
  h3g_put(h3, &n, h3g_grease_138, sizeof h3g_grease_138);
  h3g_put_connect(h3, sizeof h3, &n);
  h3g_deliver(&f, h3, 0, n, 0);
  CHECK(h3g_is_connect(&f));
}

/* A GREASE frame split mid-header across deliveries: wait, then answer. */
static void test_h3reqgrease_split(void) {
  static struct h3g_fix f;
  u8                    h3[512];
  usz                   n = 0;
  f                       = (struct h3g_fix){0};
  h3g_put(h3, &n, h3g_grease_fa, sizeof h3g_grease_fa);
  h3g_put_connect(h3, sizeof h3, &n);
  h3g_deliver(&f, h3, 0, 2, 0); /* 40 fa: length varint still missing */
  CHECK(f.got == 0);
  h3g_deliver(&f, h3, 2, 2, 0); /* 00 + HEADERS type: HEADERS incomplete */
  CHECK(f.got == 0);
  h3g_deliver(&f, h3, 4, n - 4, 0);
  CHECK(h3g_is_connect(&f));
}

/* RFC 9114 4.1: DATA before HEADERS is H3_FRAME_UNEXPECTED, never skipped. */
static void test_h3reqgrease_data_first_rejected(void) {
  static struct h3g_fix f;
  static const u8       data[] = {0x00, 0x01, 0x78};
  u8                    h3[512];
  usz                   n = 0;
  f                       = (struct h3g_fix){0};
  h3g_put(h3, &n, data, sizeof data);
  h3g_put_connect(h3, sizeof h3, &n);
  h3g_deliver(&f, h3, 0, n, 0);
  CHECK(f.got == 0);
  h3g_deliver(&f, h3, n, 0, 1);
  CHECK(f.got == 0);
  CHECK(f.req.frame_unexpected == 1);
}

void test_h3reqgrease(void) {
  test_h3reqgrease_then_connect();
  test_h3reqgrease_two_frames();
  test_h3reqgrease_split();
  test_h3reqgrease_data_first_rejected();
}
