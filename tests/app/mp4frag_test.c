#include "app/media/mp4frag/mp4frag.h"

#include "common/bytes/util/be.h"
#include "test.h"

/* Appends one box (size + type + n filler bytes) at *off, returns its
 * start. */
static usz mp4frag_test_box(u8* buf, usz* off, const char* type, usz n) {
  usz at = *off;
  be_put_be32(buf + at, (u32)(8 + n));
  for (usz i = 0; i < 4; i++) buf[at + 4 + i] = (u8)type[i];
  for (usz i = 0; i < n; i++) buf[at + 8 + i] = (u8)(0xA0 + i);
  *off = at + 8 + n;
  return at;
}

/* ftyp(12) moov(20) moof(16) mdat(40) moof(8) mdat(24): init = first
 * 2 boxes, two fragments spanning each moof+mdat pair exactly. */
static void test_mp4frag_scan_two_fragments(void) {
  u8  buf[256];
  usz off = 0;
  mp4frag_test_box(buf, &off, "ftyp", 12);
  mp4frag_test_box(buf, &off, "moov", 20);
  usz f0 = mp4frag_test_box(buf, &off, "moof", 16);
  mp4frag_test_box(buf, &off, "mdat", 40);
  usz f1 = mp4frag_test_box(buf, &off, "moof", 8);
  mp4frag_test_box(buf, &off, "mdat", 24);
  mp4frag_layout l;
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 1);
  CHECK(l.init.p == buf && l.init.n == 8 + 12 + 8 + 20);
  CHECK(l.n_frags == 2);
  CHECK(l.frags[0].p == buf + f0 && l.frags[0].n == (8 + 16) + (8 + 40));
  CHECK(l.frags[1].p == buf + f1 && l.frags[1].n == (8 + 8) + (8 + 24));
}

/* A free box between fragments (and one before moov) is skipped, not
 * counted and not folded into a fragment. */
static void test_mp4frag_scan_skips_free_boxes(void) {
  u8  buf[256];
  usz off = 0;
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "free", 4);
  mp4frag_test_box(buf, &off, "moov", 4);
  usz f0 = mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  mp4frag_test_box(buf, &off, "free", 4);
  usz f1 = mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  mp4frag_layout l;
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 1);
  CHECK(l.init.n == 3 * 12);
  CHECK(l.n_frags == 2);
  CHECK(l.frags[0].p == buf + f0 && l.frags[0].n == 24);
  CHECK(l.frags[1].p == buf + f1 && l.frags[1].n == 24);
}

static usz mp4frag_test_valid(u8* buf) {
  usz off = 0;
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "moov", 4);
  mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  return off;
}

/* Malformed shapes all return 0: a moof not followed by mdat, a box
 * whose size runs past the end, a size below 8, size 1 (largesize) and
 * size 0 (to-end), no fragment at all, no moov at all. */
static void test_mp4frag_scan_rejects_malformed(void) {
  u8             buf[128];
  mp4frag_layout l;
  usz            n = mp4frag_test_valid(buf);

  buf[24 + 4] = 'f'; /* rename moof->foof: a valid file with 0 fragments */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n           = mp4frag_test_valid(buf);
  buf[36 + 4] = 'x'; /* mdat -> xdat: moof without mdat */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 36, 100); /* mdat size past the end */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 24, 7); /* size below the 8-byte header */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 24, 1); /* largesize */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 36, 0); /* to-end-of-file */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  usz off = 0; /* init only, no fragment */
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "moov", 4);
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 0);

  off = 0; /* no moov */
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 0);

  CHECK(mp4frag_scan(wired_span_of(buf, 0), &l) == 0);
}

/* One more fragment than MP4FRAG_MAX_FRAGS is refused. */
static void test_mp4frag_scan_rejects_too_many(void) {
  static u8      buf[8 + 8 + (MP4FRAG_MAX_FRAGS + 1) * 16];
  usz            off = 0;
  mp4frag_layout l;
  mp4frag_test_box(buf, &off, "ftyp", 0);
  mp4frag_test_box(buf, &off, "moov", 0);
  for (usz i = 0; i < MP4FRAG_MAX_FRAGS; i++) {
    mp4frag_test_box(buf, &off, "moof", 0);
    mp4frag_test_box(buf, &off, "mdat", 0);
  }
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 1);
  CHECK(l.n_frags == MP4FRAG_MAX_FRAGS);
  mp4frag_test_box(buf, &off, "moof", 0);
  mp4frag_test_box(buf, &off, "mdat", 0);
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 0);
}

void test_mp4frag(void) {
  test_mp4frag_scan_two_fragments();
  test_mp4frag_scan_skips_free_boxes();
  test_mp4frag_scan_rejects_malformed();
  test_mp4frag_scan_rejects_too_many();
}
