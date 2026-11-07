#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/vi/moqvi.h"
#include "test.h"

/* draft-ietf-moq-transport-23 fetch stream deltas (11.4): Object ID
 * Delta + 2 inside a Group (11.4.1.1), delta-encoded End of Range
 * (11.4.2.1), End of Gone Range 0x40C, End of Group 0x80 / End of Track
 * 0x81 (11.4.2.2). A sequence without d23 keeps the draft-22 decoding. */

static moqfetch_seq mf23_seq(int d23, int descending) {
  moqfetch_seq s  = {0};
  s.d23           = d23;
  s.descending    = descending;
  s.eor_timed_out = 1;
  return s;
}

static int mf23_one(const u8* b, usz n, moqfetch_seq* seq, moqfetch_obj* o) {
  usz off = 0;
  int r   = moqfetch_obj_take(wired_span_of(b, n), &off, seq, o);
  if (r == MOQCTL_OK) {
    CHECK(off == n);
  }
  return r;
}

/* 11.4.1.1: no Group ID Delta -> prior + Object ID Delta + 2 (22: + 0). */
static void test_moqfetch23_object_delta(void) {
  static const u8 first[] = {0x1c, 0x05, 0x02, 0x00, 0x00};
  static const u8 o_d3[]  = {0x04, 0x03, 0x00};
  static const u8 o_d0[]  = {0x04, 0x00, 0x00};
  static const u8 none[]  = {0x00, 0x00};
  moqfetch_seq    s23     = mf23_seq(1, 0);
  moqfetch_seq    s22     = mf23_seq(0, 0);
  moqfetch_obj    o;
  CHECK(mf23_one(first, sizeof first, &s23, &o) == MOQCTL_OK);
  CHECK(mf23_one(o_d3, sizeof o_d3, &s23, &o) == MOQCTL_OK);
  CHECK(o.group == 5 && o.object == 7);
  CHECK(mf23_one(o_d0, sizeof o_d0, &s23, &o) == MOQCTL_OK);
  CHECK(o.object == 9);
  CHECK(mf23_one(none, sizeof none, &s23, &o) == MOQCTL_OK);
  CHECK(o.object == 10);
  CHECK(mf23_one(first, sizeof first, &s22, &o) == MOQCTL_OK);
  CHECK(mf23_one(o_d3, sizeof o_d3, &s22, &o) == MOQCTL_OK);
  CHECK(o.object == 5);
}

/* 11.4.1.1: prior + Delta + 2 past 2^64-1 is DELTA_ENCODING_OVERFLOW. */
static void test_moqfetch23_object_overflow(void) {
  u8              b[32];
  usz             n      = 0;
  static const u8 o_d0[] = {0x04, 0x00, 0x00};
  static const u8 none[] = {0x00, 0x00};
  moqfetch_seq    s      = mf23_seq(1, 0);
  moqfetch_obj    o;
  b[n++] = 0x1c;
  CHECK(moqvi_put(wired_mspan_of(b, sizeof b), &n, 1));
  CHECK(moqvi_put(wired_mspan_of(b, sizeof b), &n, ~0ULL - 2));
  b[n++] = 0;
  b[n++] = 0;
  CHECK(mf23_one(b, n, &s, &o) == MOQCTL_OK);
  CHECK(mf23_one(o_d0, sizeof o_d0, &s, &o) == MOQCTL_OK);
  CHECK(o.object == ~0ULL);
  s.object = ~0ULL - 1;
  CHECK(mf23_one(o_d0, sizeof o_d0, &s, &o) == MOQCTL_R_DELTA);
  CHECK(mf23_one(none, sizeof none, &s, &o) == MOQCTL_OK);
}

/* 11.4.2.1: the first End of Range is absolute; later ones add the Group
 * delta (subtract when Descending), and a zero Group delta puts the
 * Object at prior + Object delta + 1, else the Object delta is absolute. */
static void test_moqfetch23_eor_delta(void) {
  static const u8 abs[]  = {0x80, 0x8c, 0x02, 0x03};
  static const u8 same[] = {0x81, 0x0c, 0x00, 0x04};
  static const u8 next[] = {0x81, 0x0c, 0x01, 0x05};
  moqfetch_seq    s      = mf23_seq(1, 0);
  moqfetch_seq    s22    = mf23_seq(0, 0);
  moqfetch_obj    o;
  CHECK(mf23_one(abs, sizeof abs, &s, &o) == MOQCTL_OK);
  CHECK(o.flags == MOQFETCH_EOR_NONEXISTENT && o.group == 2 && o.object == 3);
  CHECK(mf23_one(same, sizeof same, &s, &o) == MOQCTL_OK);
  CHECK(o.group == 2 && o.object == 8);
  CHECK(mf23_one(next, sizeof next, &s, &o) == MOQCTL_OK);
  CHECK(o.group == 3 && o.object == 5 && s.group == 3 && s.object == 5);
  s = mf23_seq(1, 1);
  CHECK(mf23_one(abs, sizeof abs, &s, &o) == MOQCTL_OK);
  CHECK(mf23_one(next, sizeof next, &s, &o) == MOQCTL_OK);
  CHECK(o.group == 1 && o.object == 5);
  CHECK(mf23_one(abs, sizeof abs, &s22, &o) == MOQCTL_OK);
  CHECK(mf23_one(same, sizeof same, &s22, &o) == MOQCTL_OK);
  CHECK(o.group == 0 && o.object == 4);
}

/* 11.4.2.1: a decoded ID below 0 or past 2^64-1 is
 * DELTA_ENCODING_OVERFLOW. */
static void test_moqfetch23_eor_overflow(void) {
  static const u8 g1[]   = {0x81, 0x0c, 0x01, 0x00};
  static const u8 same[] = {0x81, 0x0c, 0x00, 0x00};
  moqfetch_seq    s      = mf23_seq(1, 1);
  moqfetch_obj    o;
  s.have_loc = 1;
  s.group    = 0;
  CHECK(mf23_one(g1, sizeof g1, &s, &o) == MOQCTL_R_DELTA);
  s.descending = 0;
  s.group      = ~0ULL;
  CHECK(mf23_one(g1, sizeof g1, &s, &o) == MOQCTL_R_DELTA);
  s.group  = 4;
  s.object = ~0ULL;
  CHECK(mf23_one(same, sizeof same, &s, &o) == MOQCTL_R_DELTA);
}

/* 11.4.1 Table 8: 0x40C End of Gone Range, draft-23 only. */
static void test_moqfetch23_gone(void) {
  static const u8 gone[] = {0x84, 0x0c, 0x02, 0x03};
  moqfetch_seq    s      = mf23_seq(1, 0);
  moqfetch_seq    s22    = mf23_seq(0, 0);
  moqfetch_obj    o;
  CHECK(mf23_one(gone, sizeof gone, &s22, &o) == MOQCTL_R_OBJ);
  CHECK(mf23_one(gone, sizeof gone, &s, &o) == MOQCTL_OK);
  CHECK(o.flags == MOQFETCH_EOR_GONE && o.group == 2 && o.object == 3);
}

/* 11.4.2.2: 0x80 / 0x81 carry no other field and set the prior Object ID
 * to 2^64-1, so the next Object needs a Group ID Delta. With no prior
 * Object there is nothing to end (MALFORMED_OBJECT); draft-22 has
 * neither value. */
static void test_moqfetch23_end_of_group(void) {
  static const u8 first[] = {0x1c, 0x05, 0x02, 0x00, 0x00};
  static const u8 eog[]   = {0x80, 0x80};
  static const u8 eot[]   = {0x80, 0x81};
  static const u8 none[]  = {0x00, 0x00};
  static const u8 o_d0[]  = {0x04, 0x00, 0x00};
  static const u8 g0[]    = {0x0c, 0x00, 0x00, 0x00};
  moqfetch_seq    s       = mf23_seq(1, 0);
  moqfetch_seq    s22     = mf23_seq(0, 0);
  moqfetch_obj    o;
  CHECK(mf23_one(eog, sizeof eog, &s, &o) == MOQCTL_R_OBJ);
  CHECK(mf23_one(first, sizeof first, &s, &o) == MOQCTL_OK);
  CHECK(mf23_one(eog, sizeof eog, &s, &o) == MOQCTL_OK);
  CHECK(o.flags == MOQFETCH_END_OF_GROUP && o.group == 5);
  CHECK(o.object == ~0ULL && !o.has_subgroup && o.payload.n == 0);
  CHECK(mf23_one(none, sizeof none, &s, &o) == MOQCTL_R_DELTA);
  CHECK(mf23_one(o_d0, sizeof o_d0, &s, &o) == MOQCTL_R_DELTA);
  CHECK(mf23_one(g0, sizeof g0, &s, &o) == MOQCTL_OK);
  CHECK(o.group == 6 && o.object == 0 && o.priority == 0);
  CHECK(mf23_one(eot, sizeof eot, &s, &o) == MOQCTL_OK);
  CHECK(o.flags == MOQFETCH_END_OF_TRACK && o.group == 6);
  CHECK(mf23_one(first, sizeof first, &s22, &o) == MOQCTL_OK);
  CHECK(mf23_one(eog, sizeof eog, &s22, &o) == MOQCTL_R_OBJ);
  CHECK(mf23_one(eot, sizeof eot, &s22, &o) == MOQCTL_R_OBJ);
}

/* Encodes objs[0..n) on a draft-23 sequence, expects want, then decodes
 * it back to the same Locations. */
static void mf23_roundtrip(
    const moqfetch_obj* objs, usz n, const u8* want, usz want_n) {
  moqfetch_seq enc = mf23_seq(1, 0);
  moqfetch_seq dec = mf23_seq(1, 0);
  u8           out[64];
  usz          len = 0, off = 0;
  for (usz i = 0; i < n; i++) {
    CHECK(moqfetch_obj_put(
        wired_mspan_of(out, sizeof out), &len, &enc, &objs[i]));
  }
  CHECK(len == want_n);
  for (usz i = 0; i < len && i < want_n; i++) {
    CHECK(out[i] == want[i]);
  }
  for (usz i = 0; i < n; i++) {
    moqfetch_obj d;
    CHECK(
        moqfetch_obj_take(wired_span_of(out, len), &off, &dec, &d) ==
        MOQCTL_OK);
    CHECK(d.flags == objs[i].flags && d.group == objs[i].group);
  }
  CHECK(off == len);
}

/* The encoder writes the draft-23 deltas: {5,2} absolute, {5,7} as
 * delta 3, {5,8} with no Object ID Delta, Gone through {5,10} as delta
 * {0,1}, Unknown through {7,4} as delta {2,4}, then End of Track. */
static void test_moqfetch23_put(void) {
  moqfetch_obj    o[6]   = {0};
  static const u8 want[] = {0x1c, 0x05, 0x02, 0x00, 0x00, 0x14, 0x03, 0x00,
                            0x00, 0x10, 0x00, 0x00, 0x84, 0x0c, 0x00, 0x01,
                            0x81, 0x0c, 0x02, 0x04, 0x80, 0x81};
  o[0].flags             = 0x1c;
  o[0].group             = 5;
  o[0].object            = 2;
  o[1].flags             = 0x14;
  o[1].group             = 5;
  o[1].object            = 7;
  o[2].flags             = 0x10;
  o[2].group             = 5;
  o[2].object            = 8;
  o[3].flags             = MOQFETCH_EOR_GONE;
  o[3].group             = 5;
  o[3].object            = 10;
  o[4].flags             = MOQFETCH_EOR_UNKNOWN;
  o[4].group             = 7;
  o[4].object            = 4;
  o[5].flags             = MOQFETCH_END_OF_TRACK;
  o[5].group             = 7;
  mf23_roundtrip(o, 6, want, sizeof want);
}

/* moqfetch_object_flag: a draft-23 stream omits the Object ID Delta for
 * the next Object of the same Group (a present Delta skips at least one);
 * otherwise, and on every draft-22 stream, the Delta is written. A put
 * that still asks for it there is refused. */
static void test_moqfetch23_object_flag(void) {
  moqfetch_seq s = mf23_seq(1, 0);
  moqfetch_obj o = {0};
  u8           out[16];
  usz          n = 0;
  s.have_loc     = 1;
  s.group        = 5;
  s.object       = 2;
  CHECK(moqfetch_object_flag(&s, 5, 3) == 0);
  CHECK(moqfetch_object_flag(&s, 5, 4) == MOQFETCH_F_OBJECT);
  CHECK(moqfetch_object_flag(&s, 6, 3) == MOQFETCH_F_OBJECT);
  s.d23 = 0;
  CHECK(moqfetch_object_flag(&s, 5, 3) == MOQFETCH_F_OBJECT);
  s.d23    = 1;
  o.flags  = MOQFETCH_F_OBJECT | MOQFETCH_F_PRIORITY;
  o.group  = 5;
  o.object = 3;
  CHECK(!moqfetch_obj_put(wired_mspan_of(out, sizeof out), &n, &s, &o));
  s.have_loc = 0;
  CHECK(moqfetch_object_flag(&s, 5, 3) == MOQFETCH_F_OBJECT);
}

void test_moqfetch_d23(void) {
  test_moqfetch23_object_delta();
  test_moqfetch23_object_overflow();
  test_moqfetch23_eor_delta();
  test_moqfetch23_eor_overflow();
  test_moqfetch23_gone();
  test_moqfetch23_end_of_group();
  test_moqfetch23_put();
  test_moqfetch23_object_flag();
}
