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
  u8        s[303]; /* bw_frame always writes the full plen payload too */
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

/* RFC 9114 7.2.4-7.2.7 / 11.2.1: a request stream must not carry the
 * control-stream frames (CANCEL_PUSH, SETTINGS, GOAWAY, MAX_PUSH_ID), a
 * PUSH_PROMISE from a client, or a reserved HTTP/2 type -- each is
 * H3_FRAME_UNEXPECTED; the DATA before it was still delivered and nothing
 * after it is. */
static void test_bodywin_forbidden_frame_unexpected(void) {
  static const u64 types[] = {0x3, 0x4, 0x7, 0xd, 0x5, 0x2, 0x6, 0x8, 0x9};
  for (usz k = 0; k < sizeof types / sizeof types[0]; k++) {
    static u8 buf[BODYWIN_CAP];
    bodywin   w = {0};
    bw_rec    r = {0};
    u8        s[32];
    usz       n = 0;
    bw_frame(s, &n, 0x00, 2, 'a');
    bw_frame(s, &n, types[k], 1, 0);
    bw_frame(s, &n, 0x00, 2, 'b');
    bw_land(&w, buf, s, 0, n, 1);
    CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_FRAME_UNEXPECTED);
    CHECK(r.calls == 1 && r.got_n == 2 && r.fins[0] == 0);
  }
}

/* Trailer HEADERS (and unknown types) after the body stay skipped. */
static void test_bodywin_trailers_skipped(void) {
  static u8 buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  u8        s[32];
  usz       n = 0;
  bw_frame(s, &n, 0x00, 2, 'a');
  bw_frame(s, &n, 0x01, 3, 't');
  bw_land(&w, buf, s, 0, n, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_DONE);
  CHECK(r.got_n == 2 && r.fins[r.calls - 1] == 1);
}

/* A window packed with 2-byte empty frames is parsed in one pump and slid
 * once to its end. */
static void test_bodywin_window_of_empty_frames(void) {
  static u8 s[BODYWIN_CAP], buf[BODYWIN_CAP];
  bodywin   w = {0};
  bw_rec    r = {0};
  usz       n = 0;
  while (n < BODYWIN_CAP) bw_frame(s, &n, 0x21, 0, 0);
  bw_land(&w, buf, s, 0, n, 1);
  CHECK(bodywin_pump(&w, buf, bw_sink, &r) == BODYWIN_DONE);
  CHECK(w.base == BODYWIN_CAP && bodywin_frontier(&w) == 0);
  CHECK(r.calls == 1 && r.fins[0] == 1);
}

/* Records every capsule bodywin_capsules hands over; returns 0 on call
 * number reject_at (1-based; 0 never rejects). */
typedef struct {
  u64 types[8];
  usz lens[8];
  u8  last[BODYWIN_CAPSULE_CAP];
  usz calls;
  usz reject_at;
} bw_caprec;

static int bw_cap(void* ctx, u64 type, wired_span value) {
  bw_caprec* r = ctx;
  if (r->calls < 8) {
    r->types[r->calls] = type;
    r->lens[r->calls]  = value.n;
  }
  for (usz i = 0; i < value.n; i++) r->last[i] = value.p[i];
  r->calls++;
  return r->calls != r->reject_at;
}

/* WT_MAX_DATA (type 0x190b4d3d, a 4-byte varint per RFC 9000 16) with
 * Length 1 and value 42 -- six capsule bytes. */
#define BW_MAXDATA 0x99, 0x0b, 0x4d, 0x3d, 0x01, 0x2a

static int bw_cap_is_maxdata(const bw_caprec* r, usz i) {
  return r->types[i] == 0x190b4d3dULL && r->lens[i] == 1;
}

/* RFC 9297 3.2: in HTTP/3 the capsules are the DATA frames' payload -- a
 * capsule inside one DATA frame (type 0x00, Length 6) is handed over whole
 * and the window slides past the frame. */
static void test_bodywin_capsule_in_data_frame(void) {
  static const u8     s[] = {0x00, 0x06, BW_MAXDATA};
  static u8           buf[BODYWIN_CAP];
  static bodywin_capq q;
  bodywin             w = {0};
  bw_caprec           r = {0};
  q                     = (bodywin_capq){0};
  bw_land(&w, buf, s, 0, sizeof s, 0);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_OPEN);
  CHECK(r.calls == 1 && bw_cap_is_maxdata(&r, 0) && r.last[0] == 0x2a);
  CHECK(w.base == sizeof s);
}

/* A capsule may straddle DATA frames, with an unknown (reserved 0x21)
 * frame between them (RFC 9114 7.2.8: skipped) -- still one capsule. */
static void test_bodywin_capsule_split_across_data_frames(void) {
  static const u8     s[] = {0x00, 0x03, 0x99, 0x0b, 0x4d, 0x21, 0x01,
                             0xff, 0x00, 0x03, 0x3d, 0x01, 0x2a};
  static u8           buf[BODYWIN_CAP];
  static bodywin_capq q;
  bodywin             w = {0};
  bw_caprec           r = {0};
  q                     = (bodywin_capq){0};
  bw_land(&w, buf, s, 0, 5, 0);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_OPEN);
  CHECK(r.calls == 0); /* only the capsule's first 3 bytes so far */
  bw_land(&w, buf, s, 5, sizeof s - 5, 0);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_OPEN);
  CHECK(r.calls == 1 && bw_cap_is_maxdata(&r, 0) && r.last[0] == 0x2a);
}

/* Raw capsule bytes with no DATA frame around them are not capsules: 0x2843
 * there is an unknown HTTP/3 frame type, skipped. */
static void test_bodywin_capsule_raw_bytes_not_read(void) {
  static const u8     s[] = {0x68, 0x43, 0x00};
  static u8           buf[BODYWIN_CAP];
  static bodywin_capq q;
  bodywin             w = {0};
  bw_caprec           r = {0};
  q                     = (bodywin_capq){0};
  bw_land(&w, buf, s, 0, sizeof s, 0);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_OPEN);
  CHECK(r.calls == 0);
}

/* RFC 9297 3.3: the stream ending inside a capsule is an error even when
 * the DATA frame itself is whole; ending on a capsule boundary is not. */
static void test_bodywin_capsule_fin_inside_is_error(void) {
  static const u8     cut[] = {0x00, 0x03, 0x99, 0x0b, 0x4d};
  static const u8     ok[]  = {0x00, 0x06, BW_MAXDATA};
  static u8           buf[BODYWIN_CAP];
  static bodywin_capq q;
  bodywin             w = {0};
  bw_caprec           r = {0};
  q                     = (bodywin_capq){0};
  bw_land(&w, buf, cut, 0, sizeof cut, 1);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_FRAME_ERROR);
  CHECK(r.calls == 0);
  w = (bodywin){0};
  q = (bodywin_capq){0};
  bw_land(&w, buf, ok, 0, sizeof ok, 1);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_DONE);
  CHECK(r.calls == 1);
}

/* The largest known capsule, WT_CLOSE_SESSION with a 1024-byte message
 * (type 0x2843, Length 1028 = 0x44 0x04), is handed over whole. */
static void test_bodywin_capsule_largest_known_whole(void) {
  static u8           s[BODYWIN_CAP], buf[BODYWIN_CAP];
  static bodywin_capq q;
  bodywin             w = {0};
  bw_caprec           r = {0};
  usz                 n = 0;
  q                     = (bodywin_capq){0};
  n += varint_encode(s + n, 0x00);
  n += varint_encode(s + n, 4 + 1028);
  n += varint_encode(s + n, 0x2843);
  n += varint_encode(s + n, 1028);
  for (usz i = 0; i < 1028; i++) s[n++] = (u8)i;
  bw_land(&w, buf, s, 0, n, 0);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_OPEN);
  CHECK(r.calls == 1 && r.types[0] == 0x2843 && r.lens[0] == 1028);
  CHECK(r.last[1027] == (u8)1027);
}

/* A capsule too large to hold is announced with an empty value and its
 * bytes skipped by length across DATA frames; the next one still lands. */
static void test_bodywin_capsule_oversized_skipped(void) {
  static u8           s[BODYWIN_CAP], buf[BODYWIN_CAP];
  static bodywin_capq q;
  bodywin             w   = {0};
  bw_caprec           r   = {0};
  usz                 n   = 0;
  usz                 big = BODYWIN_CAPSULE_CAP;
  q                       = (bodywin_capq){0};
  n += varint_encode(s + n, 0x00);
  n += varint_encode(s + n, 3 + 600);
  n += varint_encode(s + n, 0x21);
  n += varint_encode(s + n, big);
  for (usz i = 0; i < 600; i++) s[n++] = 0xee;
  bw_frame(s, &n, 0x00, big - 600, 0xee);
  s[n++] = 0x00;
  s[n++] = 0x06;
  for (usz i = 0; i < 6; i++) s[n++] = (u8[]){BW_MAXDATA}[i];
  bw_land(&w, buf, s, 0, n, 0);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_OPEN);
  CHECK(r.calls == 2 && r.types[0] == 0x21 && r.lens[0] == 0);
  CHECK(bw_cap_is_maxdata(&r, 1));
}

/* The receiver returning 0 stops the walk: BODYWIN_REJECTED. */
static void test_bodywin_capsule_reject(void) {
  static const u8     s[] = {0x00, 0x0c, BW_MAXDATA, BW_MAXDATA};
  static u8           buf[BODYWIN_CAP];
  static bodywin_capq q;
  bodywin             w = {0};
  bw_caprec           r = {0};
  q                     = (bodywin_capq){0};
  r.reject_at           = 1;
  bw_land(&w, buf, s, 0, sizeof s, 0);
  CHECK(bodywin_capsules(&w, buf, &q, bw_cap, &r) == BODYWIN_REJECTED);
  CHECK(r.calls == 1);
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
  test_bodywin_forbidden_frame_unexpected();
  test_bodywin_trailers_skipped();
  test_bodywin_window_of_empty_frames();
  test_bodywin_capsule_in_data_frame();
  test_bodywin_capsule_split_across_data_frames();
  test_bodywin_capsule_raw_bytes_not_read();
  test_bodywin_capsule_fin_inside_is_error();
  test_bodywin_capsule_largest_known_whole();
  test_bodywin_capsule_oversized_skipped();
  test_bodywin_capsule_reject();
}
