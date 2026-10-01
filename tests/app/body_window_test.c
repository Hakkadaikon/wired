#include "app/http3/server/srvloop/body_window.h"

#include "common/bytes/varint/varint.h"
#include "test.h"

/* A sink that records every chunk: bytes concatenated into got[], one
 * entry per call in lens[]/fins[], and returns 0 on call number reject_at
 * (1-based; 0 never rejects). */
typedef struct {
  u8  got[4 * BODYWIN_CAP];
  usz got_n;
  usz lens[64];
  int fins[64];
  usz calls;
  usz reject_at;
} bw_rec;

static int bw_sink(void* ctx, wired_span chunk, int fin) {
  bw_rec* r = ctx;
  for (usz i = 0; i < chunk.n; i++) r->got[r->got_n++] = chunk.p[i];
  if (r->calls < 64) {
    r->lens[r->calls] = chunk.n;
    r->fins[r->calls] = fin;
  }
  r->calls++;
  return r->calls != r->reject_at;
}

/* Append frame (type, payload of n bytes of value v) at s[*n]. */
static void bw_frame(u8* s, usz* n, u64 type, usz plen, u8 v) {
  *n += varint_encode(s + *n, type);
  *n += varint_encode(s + *n, plen);
  for (usz i = 0; i < plen; i++) s[(*n)++] = v;
}

static void bw_land(bodywin* w, u8* buf, const u8* s, usz off, usz n, int fin) {
  bodywin_land(w, buf, off, wired_span_of(s + off, n), fin);
}

/* S6: the window holds the largest frame header (two 8-byte varints). */
static void test_bodywin_cap_holds_largest_header(void) {
  CHECK(BODYWIN_CAP >= 16);
}

/* S1: bytes after a gap are not parsed until the gap fills. */
static void test_bodywin_gap_not_parsed(void) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  u8        s[8];
  usz       n = 0;
  bw_frame(s, &n, 0x00, 4, 0);
  s[2] = 'a';
  s[3] = 'b';
  bw_land(&w, buf, s, 0, 2, 0); /* header */
  bw_land(&w, buf, s, 3, 1, 0); /* payload byte 1, byte 0 missing */
  bodywin_pump(&w, buf, bw_sink, &r);
  CHECK(r.calls == 0);
  bw_land(&w, buf, s, 2, 1, 0);
  bodywin_pump(&w, buf, bw_sink, &r);
  CHECK(r.calls == 1 && r.got_n == 2);
  CHECK(r.got[0] == 'a' && r.got[1] == 'b' && r.fins[0] == 0);
}

/* S2: a header split one byte per packet is consumed only once whole. */
static void test_bodywin_split_header(void) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  u8        s[400];
  usz       n = 0;
  bw_frame(s, &n, 0x00, 300, 'x'); /* 1-byte type, 2-byte length */
  bw_land(&w, buf, s, 0, 1, 0);
  bw_land(&w, buf, s, 1, 1, 0);
  bodywin_pump(&w, buf, bw_sink, &r);
  CHECK(w.base == 0 && bodywin_frontier(&w) == 2 && r.calls == 0);
  bw_land(&w, buf, s, 2, n - 2, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_DONE);
  CHECK(r.got_n == 300 && r.calls == 1 && r.fins[0] == 1);
}

/* S3 + S13: a full window ending in a partial next header slides to that
 * header; credit follows base and only ever increases. */
static void test_bodywin_slides_to_partial_header(void) {
  static u8 s[2 * BODYWIN_CAP], buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  usz       n = 0;
  u64       c1, c2;
  CHECK(bodywin_credit_due(&w) == 0);
  bw_frame(s, &n, 0x00, BODYWIN_CAP - 4, 'p'); /* 3-byte header */
  bw_frame(s, &n, 0x00, 300, 'q');             /* header starts at CAP-1 */
  bw_land(&w, buf, s, 0, BODYWIN_CAP, 0);
  bodywin_pump(&w, buf, bw_sink, &r);
  CHECK(w.base == BODYWIN_CAP - 1 && bodywin_frontier(&w) == 1);
  c1 = bodywin_credit_due(&w);
  CHECK(c1 == w.base + BODYWIN_CAP);
  CHECK(bodywin_credit_due(&w) == 0);
  bw_land(&w, buf, s, BODYWIN_CAP, n - BODYWIN_CAP, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_DONE);
  CHECK(r.got_n == BODYWIN_CAP - 4 + 300);
  c2 = bodywin_credit_due(&w);
  CHECK(c2 > c1 && c2 == w.base + BODYWIN_CAP);
}

/* S7: FIN after 1 of 4 announced payload bytes is a frame error, never
 * fin=1. */
static void test_bodywin_fin_inside_frame_is_error(void) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  u8        s[8];
  usz       n = 0;
  bw_frame(s, &n, 0x00, 4, 'z');
  bw_land(&w, buf, s, 0, 3, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_FRAME_ERROR);
  CHECK(r.got_n <= 1);
  for (usz i = 0; i < r.calls; i++) CHECK(r.fins[i] == 0);
}

/* Same, FIN inside a frame header. */
static void test_bodywin_fin_inside_header_is_error(void) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  u8        s[8];
  usz       n = 0;
  bw_frame(s, &n, 0x00, 300, 'z');
  bw_land(&w, buf, s, 0, 2, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_FRAME_ERROR);
  CHECK(r.calls == 0);
}

/* Run stream s[0..n) through a fresh window, FIN on the data or (late) in
 * a separate empty frame; 1 iff it ends with on_body(empty, fin=1) after
 * got_n payload bytes. */
static int bw_ends_with_empty_fin(const u8* s, usz n, int late, usz got_n) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  bw_land(&w, buf, s, 0, n, !late);
  bodywin_pump(&w, buf, bw_sink, &r);
  bw_land(&w, buf, s, n, 0, 1);
  if (bodywin_pump(&w, buf, bw_sink, &r) != BODYWIN_DONE) return 0;
  return r.got_n == got_n && r.lens[r.calls - 1] == 0 &&
         r.fins[r.calls - 1] == 1;
}

/* S8: fin=1 arrives as an empty chunk for an empty body, a trailing
 * unknown frame, a trailing empty DATA frame, and a late empty FIN. */
static void test_bodywin_empty_fin_shapes(void) {
  u8  s[32];
  usz n = 0;
  CHECK(bw_ends_with_empty_fin(s, 0, 0, 0));
  bw_frame(s, &n, 0x00, 2, 'd');
  bw_frame(s, &n, 0x21, 3, 'u'); /* reserved/unknown type */
  CHECK(bw_ends_with_empty_fin(s, n, 0, 2));
  n = 0;
  bw_frame(s, &n, 0x00, 2, 'd');
  bw_frame(s, &n, 0x00, 0, 0);
  CHECK(bw_ends_with_empty_fin(s, n, 0, 2));
  n = 0;
  bw_frame(s, &n, 0x00, 2, 'd');
  CHECK(bw_ends_with_empty_fin(s, n, 1, 2)); /* FIN alone, later */
}

/* S10 + S11: an unknown frame is skipped; two DATA frames are two calls. */
static void test_bodywin_unknown_skipped_and_frames_split(void) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  u8        s[64];
  usz       n = 0;
  bw_frame(s, &n, 0x00, 3, 'a');
  bw_frame(s, &n, 0x21, 5, 'u');
  bw_frame(s, &n, 0x00, 2, 'b');
  bw_land(&w, buf, s, 0, n, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_DONE);
  CHECK(r.calls == 2 && r.lens[0] == 3 && r.lens[1] == 2);
  CHECK(r.got_n == 5 && r.got[3] == 'b' && r.fins[1] == 1);
}

/* S12: the sink saying stop is final -- no more calls, not even fin. */
static void test_bodywin_reject_is_final(void) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  u8        s[64];
  usz       n = 0;
  r.reject_at = 1;
  bw_frame(s, &n, 0x00, 3, 'a');
  bw_frame(s, &n, 0x00, 2, 'b');
  bw_land(&w, buf, s, 0, n, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_REJECTED);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_REJECTED);
  CHECK(r.calls == 1);
}

/* S9 + S4: a body several windows long, sent in odd-sized pieces with each
 * window's pieces in reverse order and only within credit, arrives whole and
 * in order; every credit stays <= base + cap. */
static void test_bodywin_multi_window_reordered(void) {
  static u8 s[4 * BODYWIN_CAP], want[4 * BODYWIN_CAP], buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  usz       n = 0, wn = 0, sent = 0;
  u64       credit = BODYWIN_CAP, c;
  for (usz f = 0; f < 5; f++) {
    bw_frame(s, &n, f == 2 ? 0x21 : 0x00, 700 + f * 97, 0);
    for (usz i = 0; i < 700 + f * 97; i++) s[n - 1 - i] = (u8)(f * 31 + i);
    if (f != 2)
      for (usz i = n - (700 + f * 97); i < n; i++) want[wn++] = s[i];
  }
  while (sent < n) {
    usz end = credit < n ? (usz)credit : n;
    for (usz hi = end; hi > sent;) {
      usz lo = hi > sent + 333 ? hi - 333 : sent;
      bw_land(&w, buf, s, lo, hi - lo, hi == n);
      hi = lo;
    }
    sent = end;
    bodywin_pump(&w, buf, bw_sink, &r);
    c = bodywin_credit_due(&w);
    CHECK(c == 0 || c <= w.base + BODYWIN_CAP);
    if (c) credit = c;
  }
  CHECK(w.state == BODYWIN_DONE);
  CHECK(r.got_n == wn && r.fins[r.calls - 1] == 1);
  for (usz i = 0; i < wn; i++) CHECK(r.got[i] == want[i]);
}

void test_body_window(void) {
  test_bodywin_cap_holds_largest_header();
  test_bodywin_gap_not_parsed();
  test_bodywin_split_header();
  test_bodywin_slides_to_partial_header();
  test_bodywin_fin_inside_frame_is_error();
  test_bodywin_fin_inside_header_is_error();
  test_bodywin_empty_fin_shapes();
  test_bodywin_unknown_skipped_and_frames_split();
  test_bodywin_reject_is_final();
  test_bodywin_multi_window_reordered();
}
