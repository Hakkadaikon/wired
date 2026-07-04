#include "test.h"

/* RFC 9000 5.1/5.2: route inbound datagrams to one of several live connection
 * slots by Destination Connection ID. Covers insert/find/remove and the
 * capacity/duplicate/oversized-CID edge cases. */
void test_conntable(void) {
  quic_conntable t[4];
  quic_conntable_init(t, 4);

  const u8 cid_a[] = {0xAA, 0xAA};
  const u8 cid_b[] = {0xBB, 0xBB, 0xBB};

  /* empty table: nothing found */
  CHECK(quic_conntable_find(t, 4, cid_a, 2) == -1);

  int ia = quic_conntable_insert(t, 4, cid_a, 2);
  CHECK(ia >= 0);
  CHECK(quic_conntable_find(t, 4, cid_a, 2) == ia);
  /* different CID, same length prefix: no match */
  CHECK(quic_conntable_find(t, 4, cid_b, 3) == -1);

  int ib = quic_conntable_insert(t, 4, cid_b, 3);
  CHECK(ib >= 0);
  CHECK(ib != ia);
  CHECK(quic_conntable_find(t, 4, cid_b, 3) == ib);

  /* remove frees the slot; find no longer matches */
  quic_conntable_remove(t, 4, ia);
  CHECK(quic_conntable_find(t, 4, cid_a, 2) == -1);
  /* the other connection is unaffected */
  CHECK(quic_conntable_find(t, 4, cid_b, 3) == ib);

  /* the freed slot can be reused */
  int ia2 = quic_conntable_insert(t, 4, cid_a, 2);
  CHECK(ia2 == ia);

  /* fill remaining capacity (ia2, ib already live: 2 of 4), then overflow */
  const u8 cid_c[] = {0xCC};
  const u8 cid_d[] = {0xDD};
  const u8 cid_e[] = {0xEE};
  int      ic      = quic_conntable_insert(t, 4, cid_c, 1);
  CHECK(ic >= 0);
  CHECK(quic_conntable_insert(t, 4, cid_d, 1) >= 0);  /* last free slot */
  CHECK(quic_conntable_insert(t, 4, cid_e, 1) == -1); /* table full */

  /* oversized CID is rejected regardless of free slots */
  quic_conntable_remove(t, 4, ic);
  u8 too_long[WIRED_MAX_CID_LEN + 1] = {0};
  CHECK(quic_conntable_insert(t, 4, too_long, WIRED_MAX_CID_LEN + 1) == -1);

  /* rekey replaces a live slot's CID in place (RFC 9000 7.2: the peer's
   * subsequent DCID is the locally-chosen SCID, not the Initial's DCID) */
  const u8 cid_f[] = {0xF0, 0xF1, 0xF2, 0xF3};
  CHECK(quic_conntable_rekey(t, 4, ib, cid_f, 4) == 1);
  CHECK(quic_conntable_find(t, 4, cid_b, 3) == -1); /* old key gone */
  CHECK(quic_conntable_find(t, 4, cid_f, 4) == ib); /* new key routes */

  /* rekey rejects an oversized CID and leaves the key untouched */
  CHECK(quic_conntable_rekey(t, 4, ib, too_long, WIRED_MAX_CID_LEN + 1) == 0);
  CHECK(quic_conntable_find(t, 4, cid_f, 4) == ib);

  /* rekey rejects an out-of-range index */
  CHECK(quic_conntable_rekey(t, 4, -1, cid_f, 4) == 0);
  CHECK(quic_conntable_rekey(t, 4, 4, cid_f, 4) == 0);
}
