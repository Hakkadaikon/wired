#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/ver/moqver.h"
#include "test.h"

/* @file
 * moqtail-compatible experimental track-switching extensions, draft-22
 * sessions only: Message Parameters SWITCH_FROM (0x24) and
 * SWITCHING_SET_ASSIGNMENT (0x41), Setup Option SSTS_ALGORITHMS (0x09),
 * and the REQUEST_ERROR / PUBLISH_DONE codes they use. Wire bytes are
 * hand-derived from the contract in tasks/moqt-trackswitch-plan.md SS1
 * (Type delta, Length, fields). MOQT varints (moqvi, 1..9 bytes, leading
 * 1 bits = extra bytes): 0..127 one byte, 300 = 81 2c, 0xff01 (> 16383)
 * = c0 ff 01. */

/* SUBSCRIBE + REQUEST_UPDATE (subscription): the two contexts both
 * extensions may appear in. */
#define MCSW_CTX_SUB MOQCTL_PCTX_SUBSCRIBE
#define MCSW_CTX_UPD MOQCTL_PCTX_UPDATE_SUBSCRIPTION

/* Decodes a whole Parameter list (count + params) under ver/ctx; also
 * requires the list to consume every byte on OK. */
static int mcsw_take(int ver, const u8* b, usz n, u32 ctx, moqctl_params* out) {
  usz off = 0;
  int r   = moqctl_params_take(ver, wired_span_of(b, n), &off, ctx, out);
  if (r == MOQCTL_OK && off != n) return 99;
  return r;
}

static int mcsw_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* Re-encodes a decoded list and checks it is byte-identical to want. */
static int mcsw_reencode(const moqctl_params* p, const u8* want, usz n) {
  u8  buf[128];
  usz off = 0;
  if (!moqctl_params_put(wired_mspan_of(buf, sizeof buf), &off, p)) return 0;
  return off == n && mcsw_eq(buf, want, n);
}

/* ===== SWITCH_FROM (0x24) ===== */

/* Golden from the contract, the same bytes as moqtail-rs
 * test_switch_from_wire_format (libs/moqtail-rs/src/model/parameter/
 * message_parameter.rs): request 7, Hard, Publish Done -> 24 03 07 00 80
 * (Type delta 0x24 from 0, Length 3). */
static const u8 MCSW_SW_GOLDEN[] = {0x01, 0x24, 0x03, 0x07, 0x00, 0x80};

static void test_mcsw_switch_from_golden_encode(void) {
  moqctl_params p = {0};
  u8            buf[32];
  usz           off          = 0;
  p.n                        = 1;
  p.items[0].type            = MOQCTL_PARAM_SWITCH_FROM;
  p.items[0].enc             = MOQCTL_PENC_SWITCHFROM;
  p.items[0].sw.request_id   = 7;
  p.items[0].sw.mode         = MOQCTL_SWITCH_HARD;
  p.items[0].sw.publish_done = 1;
  CHECK(moqctl_params_put(wired_mspan_of(buf, sizeof buf), &off, &p));
  CHECK(off == sizeof MCSW_SW_GOLDEN);
  CHECK(mcsw_eq(buf, MCSW_SW_GOLDEN, sizeof MCSW_SW_GOLDEN));
}

static void test_mcsw_switch_from_golden_decode(void) {
  moqctl_params       p;
  const moqctl_param* sw;
  CHECK(
      mcsw_take(
          MOQVER_D22, MCSW_SW_GOLDEN, sizeof MCSW_SW_GOLDEN, MCSW_CTX_SUB,
          &p) == MOQCTL_OK);
  sw = moqctl_params_find(&p, MOQCTL_PARAM_SWITCH_FROM);
  CHECK(sw != 0);
  if (!sw) return;
  CHECK(sw->enc == MOQCTL_PENC_SWITCHFROM);
  CHECK(sw->sw.request_id == 7);
  CHECK(sw->sw.mode == MOQCTL_SWITCH_HARD);
  CHECK(sw->sw.publish_done == 1);
  CHECK(mcsw_reencode(&p, MCSW_SW_GOLDEN, sizeof MCSW_SW_GOLDEN));
}

/* Soft, no Publish Done, a 2-byte RequestID (300 = 81 2c), decoded in
 * the REQUEST_UPDATE (subscription) context. */
static void test_mcsw_switch_from_soft_update(void) {
  static const u8 b[] = {0x01, 0x24, 0x04, 0x81, 0x2c, 0x01, 0x00};
  moqctl_params   p;
  CHECK(mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_UPD, &p) == MOQCTL_OK);
  CHECK(p.n == 1);
  CHECK(p.items[0].sw.request_id == 300);
  CHECK(p.items[0].sw.mode == MOQCTL_SWITCH_SOFT);
  CHECK(p.items[0].sw.publish_done == 0);
  CHECK(mcsw_reencode(&p, b, sizeof b));
}

static int mcsw_take_d22sub(const u8* b, usz n) {
  moqctl_params p;
  return mcsw_take(MOQVER_D22, b, n, MCSW_CTX_SUB, &p);
}

static void test_mcsw_switch_from_violations(void) {
  static const u8 mode2[]    = {0x01, 0x24, 0x03, 0x07, 0x02, 0x00};
  static const u8 flag01[]   = {0x01, 0x24, 0x03, 0x07, 0x00, 0x01};
  static const u8 flag81[]   = {0x01, 0x24, 0x03, 0x07, 0x00, 0x81};
  static const u8 flag40[]   = {0x01, 0x24, 0x03, 0x07, 0x01, 0x40};
  static const u8 trailing[] = {0x01, 0x24, 0x04, 0x07, 0x00, 0x80, 0x00};
  static const u8 noflags[]  = {0x01, 0x24, 0x02, 0x07, 0x00};
  static const u8 empty[]    = {0x01, 0x24, 0x00};
  static const u8 cutvi[]    = {0x01, 0x24, 0x01, 0x81};
  CHECK(mcsw_take_d22sub(mode2, sizeof mode2) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(flag01, sizeof flag01) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(flag81, sizeof flag81) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(flag40, sizeof flag40) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(trailing, sizeof trailing) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(noflags, sizeof noflags) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(empty, sizeof empty) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(cutvi, sizeof cutvi) == MOQCTL_VIOLATION);
}

/* Length claims more bytes than the buffer holds: the message is not
 * complete yet, same as every other Length-prefixed value. */
static void test_mcsw_switch_from_outer_truncated(void) {
  static const u8 b[] = {0x01, 0x24, 0x03, 0x07, 0x00};
  CHECK(mcsw_take_d22sub(b, sizeof b) == MOQCTL_INSUFFICIENT);
}

/* Only SUBSCRIBE / REQUEST_UPDATE(subscription), only draft-22; elsewhere
 * the Type stays unknown/out-of-scope -> VIOLATION as before. */
static void test_mcsw_switch_from_scope(void) {
  moqctl_params p;
  const u8*     g = MCSW_SW_GOLDEN;
  usz           n = sizeof MCSW_SW_GOLDEN;
  CHECK(
      mcsw_take(MOQVER_D22, g, n, MOQCTL_PCTX_PUBLISH, &p) == MOQCTL_VIOLATION);
  CHECK(mcsw_take(MOQVER_D22, g, n, MOQCTL_PCTX_FETCH, &p) == MOQCTL_VIOLATION);
  CHECK(
      mcsw_take(MOQVER_D22, g, n, MOQCTL_PCTX_UPDATE_FETCH, &p) ==
      MOQCTL_VIOLATION);
  CHECK(
      mcsw_take(MOQVER_D22, g, n, MOQCTL_PCTX_SUBSCRIBE_OK, &p) ==
      MOQCTL_VIOLATION);
  CHECK(mcsw_take(MOQVER_D19, g, n, MCSW_CTX_SUB, &p) == MOQCTL_VIOLATION);
  CHECK(mcsw_take(MOQVER_D19, g, n, MCSW_CTX_UPD, &p) == MOQCTL_VIOLATION);
  CHECK(mcsw_take(MOQVER_D18, g, n, MCSW_CTX_SUB, &p) == MOQCTL_VIOLATION);
}

/* Duplicate SWITCH_FROM in one message: not a repeatable Type. */
static void test_mcsw_switch_from_duplicate(void) {
  static const u8 b[] = {0x02, 0x24, 0x03, 0x07, 0x00, 0x80,
                         0x00, 0x03, 0x08, 0x00, 0x80};
  moqctl_params   p;
  CHECK(
      mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_SUB, &p) == MOQCTL_VIOLATION);
}

/* ===== SWITCHING_SET_ASSIGNMENT (0x41) ===== */

/* Type 0x41 = 65 still fits one byte (delta 41). Set 1, default
 * algorithm, 50 kbps (0x32), weight 3, activate 1, no Rank. */
static const u8 MCSW_SSA_NORANK[] = {0x01, 0x41, 0x05, 0x01,
                                     0x00, 0x32, 0x03, 0x01};

static void test_mcsw_ssa_norank(void) {
  moqctl_params       p;
  const moqctl_param* a;
  CHECK(
      mcsw_take(
          MOQVER_D22, MCSW_SSA_NORANK, sizeof MCSW_SSA_NORANK, MCSW_CTX_SUB,
          &p) == MOQCTL_OK);
  a = moqctl_params_find(&p, MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT);
  CHECK(a != 0);
  if (!a) return;
  CHECK(a->enc == MOQCTL_PENC_SSA);
  CHECK(a->ssa.set_id == 1);
  CHECK(a->ssa.algorithm_id == MOQCTL_SSTS_ALG_DEFAULT);
  CHECK(a->ssa.threshold_kbps == 50);
  CHECK(a->ssa.weight == 3);
  CHECK(a->ssa.activate == 1);
  CHECK(a->ssa.has_rank == 0);
  CHECK(a->ssa.rank == 0);
  CHECK(mcsw_reencode(&p, MCSW_SSA_NORANK, sizeof MCSW_SSA_NORANK));
}

/* Backpressure algorithm 0xff01 (c0 ff 01), 300 kbps (81 2c), weight
 * 10, activate 0, Rank 5: Length 1+3+2+1+1+1 = 9; REQUEST_UPDATE. */
static void test_mcsw_ssa_rank_backpressure(void) {
  static const u8 b[] = {0x01, 0x41, 0x09, 0x02, 0xc0, 0xff,
                         0x01, 0x81, 0x2c, 0x0a, 0x00, 0x05};
  moqctl_params   p;
  CHECK(mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_UPD, &p) == MOQCTL_OK);
  CHECK(p.items[0].ssa.set_id == 2);
  CHECK(p.items[0].ssa.algorithm_id == MOQCTL_SSTS_ALG_BACKPRESSURE);
  CHECK(p.items[0].ssa.threshold_kbps == 300);
  CHECK(p.items[0].ssa.weight == 10);
  CHECK(p.items[0].ssa.activate == 0);
  CHECK(p.items[0].ssa.has_rank == 1);
  CHECK(p.items[0].ssa.rank == 5);
  CHECK(mcsw_reencode(&p, b, sizeof b));
}

static void test_mcsw_ssa_violations(void) {
  static const u8 w0[]    = {0x01, 0x41, 0x05, 0x01, 0x00, 0x32, 0x00, 0x01};
  static const u8 w11[]   = {0x01, 0x41, 0x05, 0x01, 0x00, 0x32, 0x0b, 0x01};
  static const u8 trail[] = {0x01, 0x41, 0x07, 0x01, 0x00,
                             0x32, 0x03, 0x01, 0x02, 0x00};
  static const u8 cut[]   = {0x01, 0x41, 0x04, 0x01, 0x00, 0x32, 0x03};
  static const u8 empty[] = {0x01, 0x41, 0x00};
  CHECK(mcsw_take_d22sub(w0, sizeof w0) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(w11, sizeof w11) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(trail, sizeof trail) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(cut, sizeof cut) == MOQCTL_VIOLATION);
  CHECK(mcsw_take_d22sub(empty, sizeof empty) == MOQCTL_VIOLATION);
}

static void test_mcsw_ssa_scope(void) {
  moqctl_params p;
  const u8*     b = MCSW_SSA_NORANK;
  usz           n = sizeof MCSW_SSA_NORANK;
  CHECK(
      mcsw_take(MOQVER_D22, b, n, MOQCTL_PCTX_PUBLISH, &p) == MOQCTL_VIOLATION);
  CHECK(
      mcsw_take(MOQVER_D22, b, n, MOQCTL_PCTX_TRACK_STATUS, &p) ==
      MOQCTL_VIOLATION);
  CHECK(mcsw_take(MOQVER_D19, b, n, MCSW_CTX_SUB, &p) == MOQCTL_VIOLATION);
  CHECK(mcsw_take(MOQVER_D18, b, n, MCSW_CTX_UPD, &p) == MOQCTL_VIOLATION);
}

/* Both extensions plus a standard parameter in one SUBSCRIBE list,
 * ascending Type order: SUBSCRIBER_PRIORITY 0x20 (u8 0x80), SWITCH_FROM
 * 0x24 (delta 4), SSA 0x41 (delta 0x1d). */
static void test_mcsw_mixed_list(void) {
  static const u8 b[] = {0x03, 0x20, 0x80, 0x04, 0x03, 0x09, 0x01, 0x00,
                         0x1d, 0x05, 0x01, 0x00, 0x32, 0x03, 0x01};
  moqctl_params   p;
  CHECK(mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_SUB, &p) == MOQCTL_OK);
  CHECK(p.n == 3);
  CHECK(p.items[0].u8v == 0x80);
  CHECK(p.items[1].sw.request_id == 9);
  CHECK(p.items[1].sw.mode == MOQCTL_SWITCH_SOFT);
  CHECK(p.items[2].ssa.weight == 3);
  CHECK(mcsw_reencode(&p, b, sizeof b));
}

/* A whole draft-22 SUBSCRIBE body carrying SWITCH_FROM decodes through
 * moqctl_subscribe_take and re-encodes identically. */
static void test_mcsw_subscribe_message(void) {
  static const u8  b[] = {0x0b,            /* Request ID 11 */
                          0x01, 0x01, 'a', /* namespace {"a"} */
                          0x01, 'v',       /* name "v" */
                          0x01, 0x24, 0x03, 0x07, 0x01, 0x80};
  moqctl_subscribe m;
  usz              off = 0;
  u8               out[64];
  usz              eoff = 0;
  CHECK(
      moqctl_subscribe_take(MOQVER_D22, wired_span_of(b, sizeof b), &off, &m) ==
      MOQCTL_OK);
  CHECK(off == sizeof b);
  CHECK(m.request_id == 11);
  CHECK(m.params.n == 1);
  CHECK(m.params.items[0].sw.mode == MOQCTL_SWITCH_SOFT);
  CHECK(m.params.items[0].sw.publish_done == 1);
  CHECK(moqctl_subscribe_encode(wired_mspan_of(out, sizeof out), &eoff, &m));
  CHECK(eoff == sizeof b);
  CHECK(mcsw_eq(out, b, sizeof b));
  off = 0;
  CHECK(
      moqctl_subscribe_take(MOQVER_D19, wired_span_of(b, sizeof b), &off, &m) ==
      MOQCTL_VIOLATION);
}

/* ===== SSTS_ALGORITHMS Setup Option (0x09) ===== */

static int mcsw_setup(const u8* b, usz n, moqctl_setup* s) {
  usz off = 0;
  int r   = moqctl_setup_take(wired_span_of(b, n), &off, s);
  if (r == MOQCTL_OK && off != n) return 99;
  return r;
}

static int mcsw_setup_reencode(const moqctl_setup* s, const u8* b, usz n) {
  u8  out[64];
  usz off = 0;
  if (!moqctl_setup_encode(wired_mspan_of(out, sizeof out), &off, s)) return 0;
  return off == n && mcsw_eq(out, b, n);
}

static void test_mcsw_ssts_absent(void) {
  static const u8 b[] = {0x08, 0x02}; /* MAX_REQUEST_UPDATES 2 only */
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 0);
  CHECK(s.ssts_alg_n == 0);
  CHECK(mcsw_setup_reencode(&s, b, sizeof b));
}

/* Present with an empty list: offered, but no algorithm. */
static void test_mcsw_ssts_zero(void) {
  static const u8 b[] = {0x09, 0x00};
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 1);
  CHECK(s.ssts_alg_n == 0);
  CHECK(mcsw_setup_reencode(&s, b, sizeof b));
}

static void test_mcsw_ssts_one(void) {
  static const u8 b[] = {0x09, 0x01, 0x00};
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 1);
  CHECK(s.ssts_alg_n == 1);
  CHECK(s.ssts_algs[0] == MOQCTL_SSTS_ALG_DEFAULT);
  CHECK(mcsw_setup_reencode(&s, b, sizeof b));
}

static void test_mcsw_ssts_two(void) {
  static const u8 b[] = {0x09, 0x04, 0x00, 0xc0, 0xff, 0x01};
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 1);
  CHECK(s.ssts_alg_n == 2);
  CHECK(s.ssts_algs[0] == MOQCTL_SSTS_ALG_DEFAULT);
  CHECK(s.ssts_algs[1] == MOQCTL_SSTS_ALG_BACKPRESSURE);
  CHECK(mcsw_setup_reencode(&s, b, sizeof b));
}

/* Ascending order with the other options: PATH "/a" (0x01), IMPLEMENTATION
 * "w" (delta 6 -> 0x07), MAX_REQUEST_UPDATES 3 (delta 1 -> 0x08), SSTS
 * (delta 1 -> 0x09) last. */
static void test_mcsw_ssts_order(void) {
  static const u8 b[] = {0x01, 0x02, '/',  'a',  0x06, 0x01, 'w',
                         0x01, 0x03, 0x01, 0x02, 0x00, 0x05};
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_path == 1);
  CHECK(s.has_implementation == 1);
  CHECK(s.max_request_updates == 3);
  CHECK(s.has_ssts == 1);
  CHECK(s.ssts_alg_n == 2);
  CHECK(s.ssts_algs[1] == 5);
  CHECK(mcsw_setup_reencode(&s, b, sizeof b));
}

/* More than MOQCTL_SSTS_MAX_ALGS unknown ids: the first
 * MOQCTL_SSTS_MAX_ALGS are kept, the rest parsed and dropped; the option
 * stays present and re-encodes lossily (documented on moqctl_setup). */
static void test_mcsw_ssts_cap(void) {
  static const u8 b[]     = {0x09, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  static const u8 lossy[] = {0x09, 0x04, 0x01, 0x02, 0x03, 0x04};
  moqctl_setup    s;
  CHECK(MOQCTL_SSTS_MAX_ALGS == 4);
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 1);
  CHECK(s.ssts_alg_n == MOQCTL_SSTS_MAX_ALGS);
  CHECK(s.ssts_algs[0] == 1);
  CHECK(s.ssts_algs[3] == 4);
  CHECK(mcsw_setup_reencode(&s, lossy, sizeof lossy));
}

/* Known ids win the cap: five unknown ids, then default and 0xff01
 * (c0 ff 01) last -> kept {0, 0xff01, 1, 2}; re-encode puts them first. */
static void test_mcsw_ssts_cap_keeps_known(void) {
  static const u8 b[]  = {0x09, 0x09, 0x01, 0x02, 0x03, 0x04,
                          0x05, 0x00, 0xc0, 0xff, 0x01};
  static const u8 re[] = {0x09, 0x06, 0x00, 0xc0, 0xff, 0x01, 0x01, 0x02};
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 1);
  CHECK(s.ssts_alg_n == 4);
  CHECK(s.ssts_algs[0] == MOQCTL_SSTS_ALG_DEFAULT);
  CHECK(s.ssts_algs[1] == MOQCTL_SSTS_ALG_BACKPRESSURE);
  CHECK(s.ssts_algs[2] == 1);
  CHECK(s.ssts_algs[3] == 2);
  CHECK(mcsw_setup_reencode(&s, re, sizeof re));
}

/* Coordinator-supplied vector 09 04 00 c0 ff 00: c0 ff 00 is the 3-byte
 * moqvi 0xff00 (110 00000 | ff | 00), NOT 0xff01 -- so it decodes to
 * {0, 0xff00}, an unknown private id after default, and round-trips. */
static void test_mcsw_ssts_vector_ff00(void) {
  static const u8 b[] = {0x09, 0x04, 0x00, 0xc0, 0xff, 0x00};
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 1);
  CHECK(s.ssts_alg_n == 2);
  CHECK(s.ssts_algs[0] == MOQCTL_SSTS_ALG_DEFAULT);
  CHECK(s.ssts_algs[1] == 0xff00);
  CHECK(mcsw_setup_reencode(&s, b, sizeof b));
}

/* A list ending mid-varint is a malformed option: ignored like an unknown
 * option (SETUP still decodes, has_ssts 0) -- the SSTS extension is simply
 * not offered, which is the safe fallback for an experimental option. */
static void test_mcsw_ssts_malformed(void) {
  static const u8 b[] = {0x09, 0x02, 0x00, 0x80}; /* 80: 2-byte, cut */
  moqctl_setup    s;
  CHECK(mcsw_setup(b, sizeof b, &s) == MOQCTL_OK);
  CHECK(s.has_ssts == 0);
  CHECK(s.ssts_alg_n == 0);
}

/* ===== Third-party (moqtail-rs) vectors ===== */

/* moqtail parameter list: SUBSCRIBER_PRIORITY 128, SWITCH_FROM(7, Hard,
 * publish_done), NEW_GROUP_REQUEST 3 (0x32 = 0x24 + delta 0x0e). */
static void test_mcsw_moqtail_list(void) {
  static const u8 b[] = {0x03, 0x20, 0x80, 0x04, 0x03,
                         0x07, 0x00, 0x80, 0x0e, 0x03};
  moqctl_params   p;
  CHECK(mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_SUB, &p) == MOQCTL_OK);
  CHECK(p.n == 3);
  CHECK(p.items[0].u8v == 128);
  CHECK(p.items[1].sw.request_id == 7);
  CHECK(p.items[1].sw.mode == MOQCTL_SWITCH_HARD);
  CHECK(p.items[1].sw.publish_done == 1);
  CHECK(p.items[2].type == MOQCTL_PARAM_NEW_GROUP_REQUEST);
  CHECK(p.items[2].vi == 3);
  CHECK(mcsw_reencode(&p, b, sizeof b));
}

/* SwitchFrom(128242, Soft, true): c1 f4 f2 = 110 00001 | f4 | f2 =
 * 0x01f4f2 = 128242; Length 3+1+1 = 5. */
static void test_mcsw_moqtail_switch_from_3byte(void) {
  static const u8 b[] = {0x01, 0x24, 0x05, 0xc1, 0xf4, 0xf2, 0x01, 0x80};
  moqctl_params   p;
  CHECK(mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_SUB, &p) == MOQCTL_OK);
  CHECK(p.items[0].sw.request_id == 128242);
  CHECK(p.items[0].sw.mode == MOQCTL_SWITCH_SOFT);
  CHECK(p.items[0].sw.publish_done == 1);
  CHECK(mcsw_reencode(&p, b, sizeof b));
}

/* moqtail always writes Rank: set 7, alg 0, 2000 kbps (87 d0 = 10 000111
 * | d0 = 0x07d0), weight 5, activate 2, rank 2; Length 7. */
static void test_mcsw_moqtail_ssa(void) {
  static const u8 b[] = {0x01, 0x41, 0x07, 0x07, 0x00,
                         0x87, 0xd0, 0x05, 0x02, 0x02};
  moqctl_params   p;
  CHECK(mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_SUB, &p) == MOQCTL_OK);
  CHECK(p.items[0].ssa.set_id == 7);
  CHECK(p.items[0].ssa.algorithm_id == 0);
  CHECK(p.items[0].ssa.threshold_kbps == 2000);
  CHECK(p.items[0].ssa.weight == 5);
  CHECK(p.items[0].ssa.activate == 2);
  CHECK(p.items[0].ssa.has_rank == 1);
  CHECK(p.items[0].ssa.rank == 2);
  CHECK(mcsw_reencode(&p, b, sizeof b));
}

/* An explicit Rank 0 is kept (has_rank 1) and re-emitted, not dropped. */
static void test_mcsw_ssa_rank_zero(void) {
  static const u8 b[] = {0x01, 0x41, 0x06, 0x07, 0x00, 0x64, 0x05, 0x02, 0x00};
  moqctl_params   p;
  CHECK(mcsw_take(MOQVER_D22, b, sizeof b, MCSW_CTX_SUB, &p) == MOQCTL_OK);
  CHECK(p.items[0].ssa.has_rank == 1);
  CHECK(p.items[0].ssa.rank == 0);
  CHECK(mcsw_reencode(&p, b, sizeof b));
}

/* moqtail switching_set_assignment_rejects_trailing_bytes: every field
 * put_vi'd, [7, 0, 100, 5, 2, 1, 0xAA] -> 07 00 64 05 02 01 80 aa
 * (0xAA = 170 > 127: 2-byte 80 aa); Length 8. */
static void test_mcsw_moqtail_ssa_trailing(void) {
  static const u8 b[] = {0x01, 0x41, 0x08, 0x07, 0x00, 0x64,
                         0x05, 0x02, 0x01, 0x80, 0xaa};
  CHECK(mcsw_take_d22sub(b, sizeof b) == MOQCTL_VIOLATION);
}

/* ===== Encoder validation ===== */

static int mcsw_put_one(const moqctl_param* item) {
  moqctl_params p = {0};
  u8            buf[64];
  usz           off = 0;
  p.n               = 1;
  p.items[0]        = *item;
  return moqctl_params_put(wired_mspan_of(buf, sizeof buf), &off, &p);
}

static void test_mcsw_encode_rejects_bad_mode(void) {
  moqctl_param it  = {0};
  it.type          = MOQCTL_PARAM_SWITCH_FROM;
  it.enc           = MOQCTL_PENC_SWITCHFROM;
  it.sw.request_id = 1;
  it.sw.mode       = MOQCTL_SWITCH_SOFT;
  CHECK(mcsw_put_one(&it) == 1);
  it.sw.mode = 2;
  CHECK(mcsw_put_one(&it) == 0);
}

static void test_mcsw_encode_rejects_bad_weight(void) {
  moqctl_param it = {0};
  it.type         = MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT;
  it.enc          = MOQCTL_PENC_SSA;
  it.ssa.weight   = 1;
  CHECK(mcsw_put_one(&it) == 1);
  it.ssa.weight = 10;
  CHECK(mcsw_put_one(&it) == 1);
  it.ssa.weight = 0;
  CHECK(mcsw_put_one(&it) == 0);
  it.ssa.weight = 11;
  CHECK(mcsw_put_one(&it) == 0);
}

/* ===== Codes ===== */

static void test_mcsw_codes(void) {
  CHECK(MOQCTL_PARAM_SWITCH_FROM == 0x24);
  CHECK(MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT == 0x41);
  CHECK(MOQCTL_OPT_SSTS_ALGORITHMS == 0x09);
  CHECK(MOQCTL_SWITCH_HARD == 0 && MOQCTL_SWITCH_SOFT == 1);
  CHECK(MOQCTL_ERR_INVALID_SWITCH == 0x32);
  CHECK(MOQCTL_ERR_INVALID_SWITCH == MOQCTL_ERR_INVALID_JOINING_REQUEST_ID);
  CHECK(MOQCTL_ERR_UNSUPPORTED_EXTENSION == 0x33);
  CHECK(MOQCTL_DONE_SWITCHED == 0x3);
  CHECK(MOQCTL_SSTS_ALG_DEFAULT == 0);
  CHECK(MOQCTL_SSTS_ALG_BACKPRESSURE == 0xff01);
  /* Send side passes the d22-only request errors through unchanged. */
  CHECK(
      moqctl_request_error_for(MOQVER_D22, MOQCTL_ERR_INVALID_SWITCH) ==
      MOQCTL_ERR_INVALID_SWITCH);
  CHECK(
      moqctl_request_error_for(MOQVER_D22, MOQCTL_ERR_UNSUPPORTED_EXTENSION) ==
      MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  /* moqctl_publish_done_for keeps mapping wire 0x3 to TRACK_ENDED on d22
   * (it reads 0x3 as SUBSCRIPTION_ENDED): a "switched" PUBLISH_DONE must
   * be written as MOQCTL_DONE_SWITCHED directly, never through it. */
  CHECK(
      moqctl_publish_done_for(MOQVER_D22, MOQCTL_DONE_SWITCHED) ==
      MOQCTL_DONE_TRACK_ENDED);
}

void test_moqctl_switch(void) {
  test_mcsw_switch_from_golden_encode();
  test_mcsw_switch_from_golden_decode();
  test_mcsw_switch_from_soft_update();
  test_mcsw_switch_from_violations();
  test_mcsw_switch_from_outer_truncated();
  test_mcsw_switch_from_scope();
  test_mcsw_switch_from_duplicate();
  test_mcsw_ssa_norank();
  test_mcsw_ssa_rank_backpressure();
  test_mcsw_ssa_violations();
  test_mcsw_ssa_scope();
  test_mcsw_mixed_list();
  test_mcsw_subscribe_message();
  test_mcsw_ssts_absent();
  test_mcsw_ssts_zero();
  test_mcsw_ssts_one();
  test_mcsw_ssts_two();
  test_mcsw_ssts_order();
  test_mcsw_ssts_cap();
  test_mcsw_ssts_cap_keeps_known();
  test_mcsw_ssts_vector_ff00();
  test_mcsw_ssts_malformed();
  test_mcsw_moqtail_list();
  test_mcsw_moqtail_switch_from_3byte();
  test_mcsw_moqtail_ssa();
  test_mcsw_ssa_rank_zero();
  test_mcsw_moqtail_ssa_trailing();
  test_mcsw_encode_rejects_bad_mode();
  test_mcsw_encode_rejects_bad_weight();
  test_mcsw_codes();
}
