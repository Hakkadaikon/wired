#include "test.h"

/* RFC 9000 19.4/19.5/19.8/19.10/19.13: a stream-affecting frame must address
 * a stream the addressed party can actually act on: for a locally initiated
 * stream, one already created (index < opened); and in the right direction
 * for what the frame requires (send vs receive capability on that stream). A
 * violation is STREAM_STATE_ERROR. */

/* A server addressed by a client-initiated stream ID never needs the
 * "already created" check (the peer's own streams are implicitly open on
 * first reference) -- only the directionality check applies. */
static void test_streamstate_peer_initiated_needs_no_creation_check(void) {
  streams s;
  streams_init(&s, 0);          /* nothing of this (irrelevant) type opened */
  u64 cid = stream_id(0, 0, 3); /* client-initiated bidi, index 3 */
  /* server (am_server=1) receiving a STREAM frame (needs_send=1 on the
   * client's part, i.e. the client must be able to send -- bidi always can)
   */
  CHECK(streamstate_ok(1, cid, 1, &s) == 1);
}

/* A locally (server) initiated stream not yet created (index >= opened) is
 * STREAM_STATE_ERROR. */
static void test_streamstate_uncreated_local_stream_rejected(void) {
  streams s;
  streams_init(&s, 10);
  streams_observe(&s, 1);           /* server has opened indices 0..1 */
  u64 not_yet = stream_id(1, 0, 5); /* server-initiated bidi, index 5 */
  CHECK(streamstate_ok(1, not_yet, 1, &s) == 0);
}

/* A locally initiated stream already created (index < opened) is fine. */
static void test_streamstate_created_local_stream_ok(void) {
  streams s;
  streams_init(&s, 10);
  streams_observe(&s, 1);          /* opened 0..1 */
  u64 exists = stream_id(1, 0, 1); /* server-initiated bidi, index 1 */
  CHECK(streamstate_ok(1, exists, 1, &s) == 1);
}

/* Wrong directionality: a server-initiated UNI stream is send-only from the
 * server's side, so a peer (client) can never legitimately need to send on
 * it -- a STREAM frame referencing it is STREAM_STATE_ERROR regardless of
 * creation state. */
static void test_streamstate_wrong_direction_rejected(void) {
  streams s;
  streams_init(&s, 10);
  streams_observe(&s, 0);        /* server has opened index 0 of this type */
  u64 suni = stream_id(1, 1, 0); /* server-initiated uni, index 0 */
  /* server receiving a frame that requires the CLIENT to be able to send on
   * suni: illegal, the client can only receive on a server-initiated uni. */
  CHECK(streamstate_ok(1, suni, 1, &s) == 0);
  /* a frame that requires the client to be able to receive (e.g.
   * MAX_STREAM_DATA/STOP_SENDING territory) is fine. */
  CHECK(streamstate_ok(1, suni, 0, &s) == 1);
}

/* Bidi streams have no directionality restriction; only creation matters. */
static void test_streamstate_bidi_no_direction_restriction(void) {
  streams s;
  streams_init(&s, 10);
  streams_observe(&s, 2);        /* opened 0..2 */
  u64 bidi = stream_id(1, 0, 2); /* server-initiated bidi, index 2 */
  CHECK(streamstate_ok(1, bidi, 1, &s) == 1);
  CHECK(streamstate_ok(1, bidi, 0, &s) == 1);
}

void test_streamstate(void) {
  test_streamstate_peer_initiated_needs_no_creation_check();
  test_streamstate_uncreated_local_stream_rejected();
  test_streamstate_created_local_stream_ok();
  test_streamstate_wrong_direction_rejected();
  test_streamstate_bidi_no_direction_restriction();
}
