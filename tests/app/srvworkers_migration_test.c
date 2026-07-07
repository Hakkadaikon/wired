#include "test.h"
#include "transport/packet/frame/frame/ncid_worker.h"

/* @file
 * tasks/core-pinning-plan.md test 12: a named acceptance test that
 * DOCUMENTS the known QUIC-migration/SO_REUSEPORT routing gap (PIN-005),
 * using the already-merged CID worker-index codec (quic_ncid_worker_encode/
 * decode) to demonstrate it concretely. This does NOT implement any
 * migration-handling logic -- that is explicitly out of scope (eBPF CID
 * steering, PIN-006). It is a regression anchor: if the CID encoding is
 * accidentally broken, or accidentally "fixed" in a way inconsistent with
 * the plan's decision to punt on migration, this test catches it.
 *
 * The "naive kernel-hash-based router" below is a MOCK of what a
 * SO_REUSEPORT 4-tuple hash conceptually does -- this SDK does not
 * implement any such router (it relies on the kernel's own reuseport
 * hashing), so this is intentionally a plain arithmetic stand-in, not a
 * production primitive. */

/* Mock of a hypothetical naive 4-tuple-hash router: NOT a real kernel hash,
 * just enough arithmetic to show a routing decision can move when the
 * 4-tuple changes (as it does on a real migration/NAT rebind). */
static u32 naive_hash_route(u32 src_ip, u32 src_port, int num_workers) {
  return (src_ip ^ src_port) % (u32)num_workers;
}

/* TEST: a CID issued to worker 2 (2-bit field, matching a 4-worker fleet)
 * still decodes as worker 2 after "migration" -- CID bits do not change on
 * migration, so this half of the story is correct by construction. */
static void test_migration_cid_bits_survive_unchanged(void) {
  u8 cid[8] = {0};
  CHECK(quic_ncid_worker_encode(cid, sizeof cid, 2, 2) == 0);
  CHECK(quic_ncid_worker_decode(cid, sizeof cid, 2) == 2);
}

/* TEST: the documented gap. Original 4-tuple (10.0.0.3, port 12345) hashes
 * to worker 2 -- assume the CID was issued by worker 2 initially wiring up
 * this connection (consistent: hash and CID agree at connection start).
 * After a NAT rebind the client's observed 4-tuple becomes
 * (10.0.0.4, port 9999); the SAME connection's CID still decodes as
 * worker 2 (bits are immutable), but the naive 4-tuple hash of the NEW
 * tuple computes worker 3 -- a real SO_REUSEPORT re-hash would steer the
 * migrated packet to a DIFFERENT worker than the one holding the
 * connection state. This disagreement is the documented, out-of-scope
 * limitation (PIN-005), not a bug in either mechanism individually. */
static void test_migration_naive_hash_disagrees_with_cid(void) {
  u8  cid[8]        = {0};
  u32 original_ip   = 0x0A000003; /* 10.0.0.3 */
  u32 original_port = 12345;
  u32 migrated_ip   = 0x0A000004; /* 10.0.0.4, post-rebind */
  u32 migrated_port = 9999;
  int num_workers   = 4;
  int cid_worker    = 2;
  u32 hash_before, hash_after, cid_after;

  CHECK(quic_ncid_worker_encode(cid, sizeof cid, 2, (u32)cid_worker) == 0);

  hash_before = naive_hash_route(original_ip, original_port, num_workers);
  hash_after  = naive_hash_route(migrated_ip, migrated_port, num_workers);
  cid_after   = (u32)quic_ncid_worker_decode(cid, sizeof cid, 2);

  CHECK((int)hash_before == cid_worker); /* agree at connection start */
  CHECK((int)cid_after == cid_worker);   /* CID bits: unchanged by migration */
  CHECK(hash_after != cid_after); /* THE GAP: kernel hash now disagrees */
  CHECK(hash_after == 3); /* exact number pinned as a regression anchor */
}

void test_srvworkers_migration(void) {
  test_migration_cid_bits_survive_unchanged();
  test_migration_naive_hash_disagrees_with_cid();
}
