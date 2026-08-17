#include "test.h"

/* RFC 9000 2.1 stream ids: 0 client-bidi, 1 server-bidi, 2 client-uni,
 * 3 server-uni. */

/* Bidirectional streams: both endpoints may send and receive, regardless of
 * who initiated. */
static void test_role_bidi(void) {
  CHECK(stream_can_send(1, 0) == 1 && stream_can_receive(1, 0) == 1);
  CHECK(stream_can_send(0, 0) == 1 && stream_can_receive(0, 0) == 1);
  CHECK(stream_can_send(1, 1) == 1 && stream_can_receive(1, 1) == 1);
  CHECK(stream_can_send(0, 1) == 1 && stream_can_receive(0, 1) == 1);
}

/* Client-initiated uni stream (id 2): client sends, server receives. */
static void test_role_client_uni(void) {
  CHECK(stream_can_send(1, 2) == 1);    /* client is initiator */
  CHECK(stream_can_receive(1, 2) == 0); /* initiator does not read */
  CHECK(stream_can_send(0, 2) == 0);    /* server cannot write */
  CHECK(stream_can_receive(0, 2) == 1); /* server reads */
}

/* Server-initiated uni stream (id 3): server sends, client receives. */
static void test_role_server_uni(void) {
  CHECK(stream_can_send(0, 3) == 1); /* server is initiator */
  CHECK(stream_can_receive(0, 3) == 0);
  CHECK(stream_can_send(1, 3) == 0); /* client cannot write */
  CHECK(stream_can_receive(1, 3) == 1);
}

void test_stream_role(void) {
  test_role_bidi();
  test_role_client_uni();
  test_role_server_uni();
}
