#include "test.h"

/* Path n: fd, 127.0.0.1:(5000 + n). */
static pathsel_key pc_key(i64 fd, u16 n) {
  pathsel_key k = {fd, {0}};
  wired_udp_addr(&k.peer, (u16)(5000 + n), (const u8[4]){127, 0, 0, 1});
  return k;
}

/* A NEW_CONNECTION_ID frame: seq, rpt, a 6-byte ID filled with b. */
static ncid_frame pc_ncid(u64 seq, u64 rpt, u8 b) {
  ncid_frame f = {seq, rpt, 6, {0}, {0}};
  for (usz i = 0; i < 6; i++) f.cid[i] = b;
  return f;
}

static void pc_pool(peercid* p) {
  static const u8 cid0[6] = {0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0};
  ncid_frame      f1      = pc_ncid(1, 0, 0xb1);
  peercid_init(p, wired_span_of(cid0, 6));
  peercid_add(p, &f1);
}

/* RFC 9000 9.5: each path gets its own ID, kept on later sends; none is
 * left for a third path. */
static void test_peercid_bind_per_path(void) {
  peercid              p;
  pathsel_key          k1 = pc_key(3, 1), k2 = pc_key(3, 2), k3 = pc_key(3, 3);
  const peercid_entry *a, *b;
  pc_pool(&p);
  a = peercid_bind(&p, &k1);
  b = peercid_bind(&p, &k2);
  CHECK(a && b && a != b);
  CHECK(a->seq == 0 && b->seq == 1);
  CHECK(peercid_bind(&p, &k1) == a);
  CHECK(peercid_of(&p, &k2) == b);
  CHECK(peercid_bind(&p, &k3) == 0);
  CHECK(peercid_of(&p, &k3) == 0);
}

/* RFC 9000 9.5 exception: a shared ID serves every path on its socket
 * only. */
static void test_peercid_share_same_socket(void) {
  peercid              p;
  pathsel_key          k1 = pc_key(3, 1), k2 = pc_key(3, 2), k4 = pc_key(4, 2);
  const peercid_entry* a;
  pc_pool(&p);
  a = peercid_bind(&p, &k1);
  CHECK(peercid_share(&p, &k1) == a);
  CHECK(peercid_of(&p, &k2) == a);
  CHECK(peercid_of(&p, &k4) == 0);
  CHECK(peercid_share(&p, &k4) == 0);
}

/* RFC 9000 9.5: a path on a shared ID's socket whose peer changed its DCID
 * binds its own ID, and from then on uses that one. */
static void test_peercid_own_beats_shared(void) {
  peercid              p;
  pathsel_key          k1 = pc_key(3, 1), k2 = pc_key(3, 2);
  const peercid_entry *a, *b;
  pc_pool(&p);
  a = peercid_bind(&p, &k1);
  peercid_share(&p, &k1);
  b = peercid_bind(&p, &k2);
  CHECK(b && b != a);
  CHECK(peercid_of(&p, &k2) == b);
  CHECK(peercid_of(&p, &k1) == a);
}

/* RFC 9000 5.1.2: Retire Prior To drops the lower IDs and owes their
 * retirement; a repeated frame is ignored. */
static void test_peercid_retire_prior_to(void) {
  peercid     p;
  pathsel_key k1 = pc_key(3, 1);
  ncid_frame  f2 = pc_ncid(2, 1, 0xb2);
  u64         seq;
  pc_pool(&p);
  peercid_bind(&p, &k1); /* seq 0 */
  peercid_add(&p, &f2);
  CHECK(peercid_of(&p, &k1) == 0);
  CHECK(peercid_take_retire(&p, &seq) == 1 && seq == 0);
  CHECK(peercid_take_retire(&p, &seq) == 0);
  peercid_add(&p, &f2); /* retransmitted frame */
  CHECK(peercid_bind(&p, &k1)->seq == 1);
  CHECK(peercid_bind(&p, &(pathsel_key){9, {0}})->seq == 2);
  CHECK(peercid_take_retire(&p, &seq) == 0);
}

/* RFC 9000 5.1.2: an ID arriving below an earlier Retire Prior To is
 * retired at once, never held. */
static void test_peercid_late_below_rpt(void) {
  peercid         p;
  ncid_frame      f2 = pc_ncid(2, 2, 0xb2), late = pc_ncid(1, 0, 0xb1);
  pathsel_key     k1 = pc_key(3, 1), k2 = pc_key(3, 2);
  u64             seq;
  static const u8 cid0[6] = {0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0};
  peercid_init(&p, wired_span_of(cid0, 6));
  peercid_add(&p, &f2);
  CHECK(peercid_take_retire(&p, &seq) == 1 && seq == 0);
  peercid_add(&p, &late);
  CHECK(peercid_take_retire(&p, &seq) == 1 && seq == 1);
  CHECK(peercid_bind(&p, &k1)->seq == 2);
  CHECK(peercid_bind(&p, &k2) == 0);
}

/* RFC 9000 5.1.1: one ID past the active limit is a
 * CONNECTION_ID_LIMIT_ERROR; a repeat of a held one is not. */
static void test_peercid_over_limit(void) {
  peercid     p;
  ncid_frame  f1 = pc_ncid(1, 0, 0xb1), f2 = pc_ncid(2, 0, 0xb2);
  pathsel_key k1 = pc_key(3, 1), k2 = pc_key(3, 2), k3 = pc_key(3, 3);
  pc_pool(&p);
  CHECK(peercid_add(&p, &f1) == 0);
  CHECK(peercid_add(&p, &f2) == ERR_CONNECTION_ID_LIMIT_ERROR);
  peercid_bind(&p, &k1);
  peercid_bind(&p, &k2);
  CHECK(peercid_bind(&p, &k3) == 0);
}

/* RFC 9000 19.15: a held sequence number carrying another ID is a
 * PROTOCOL_VIOLATION. */
static void test_peercid_seq_reuse(void) {
  peercid    p;
  ncid_frame other = pc_ncid(1, 0, 0xc1);
  pc_pool(&p);
  CHECK(peercid_add(&p, &other) == ERR_PROTOCOL_VIOLATION);
}

/* RFC 9000 5.1.2: an ID no tracked path uses is retired and freed; a
 * shared one stays while a tracked path is on its socket. */
static void test_peercid_sweep(void) {
  peercid     p;
  pathsel_key k1 = pc_key(3, 1), k2 = pc_key(3, 2), k5 = pc_key(3, 5);
  pathsel_key k3 = pc_key(4, 3);
  u64         seq;
  pc_pool(&p);
  peercid_bind(&p, &k1);
  peercid_bind(&p, &k2);
  peercid_sweep(&p, &k2, 1);
  CHECK(peercid_take_retire(&p, &seq) == 1 && seq == 0);
  CHECK(peercid_of(&p, &k2) != 0);
  CHECK(peercid_bind(&p, &k3) == 0); /* the retired ID is not reused */
  peercid_share(&p, &k2);
  peercid_sweep(&p, &k5, 1);
  CHECK(peercid_take_retire(&p, &seq) == 0);
  CHECK(peercid_of(&p, &k5) != 0);
}

void test_peercid(void) {
  test_peercid_bind_per_path();
  test_peercid_share_same_socket();
  test_peercid_own_beats_shared();
  test_peercid_retire_prior_to();
  test_peercid_late_below_rpt();
  test_peercid_over_limit();
  test_peercid_seq_reuse();
  test_peercid_sweep();
}
