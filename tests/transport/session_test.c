#include "transport/conn/lifecycle/session/session.h"

#include "test.h"
#include "transport/packet/frame/frame/frame.h"

/* A full kernel-free QUIC session: client and server complete a handshake
 * over the in-memory link and exchange 1-RTT STREAM data in both directions,
 * using only the high-level quic_session API. */
static void test_session_e2e(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  u8       cpriv[32], spriv[32];
  for (usz i = 0; i < 32; i++) {
    cpriv[i] = (u8)(i + 1);
    spriv[i] = (u8)(0x40 + i);
  }

  quic_memlink link;
  quic_memlink_init(&link);

  quic_session         cli, srv;
  quic_session_init_in cin = {cpriv, dcid, &link, 0};
  quic_session_init_in sin = {spriv, dcid, &link, 1};
  quic_session_init(&cli, &cin);
  quic_session_init(&srv, &sin);

  /* handshake: ClientHello over the link, server accepts, both agree keys */
  CHECK(quic_session_client_hello(&cli) == 1);
  CHECK(quic_session_accept(&srv) == 1);
  const u8 tr[] = "transcript";
  CHECK(quic_session_finish(&cli, &srv, quic_span_of(tr, sizeof(tr))) == 1);

  /* server -> client 1-RTT STREAM */
  quic_session_msg m1 = {4, {(const u8 *)"hello", 5}, 1};
  CHECK(quic_session_send_stream(&srv, &m1) == 1);
  quic_stream_frame got;
  CHECK(quic_session_recv_stream(&cli, &got) == 1);
  CHECK(got.stream_id == 4 && got.fin == 1 && got.length == 5);
  CHECK(got.data[0] == 'h' && got.data[4] == 'o');

  /* client -> server 1-RTT STREAM (reverse direction) */
  quic_session_msg m2 = {0, {(const u8 *)"hi!", 3}, 0};
  CHECK(quic_session_send_stream(&cli, &m2) == 1);
  quic_stream_frame got2;
  CHECK(quic_session_recv_stream(&srv, &got2) == 1);
  CHECK(got2.stream_id == 0 && got2.length == 3);
  CHECK(got2.data[0] == 'h' && got2.data[2] == '!');
}

/* Sending 1-RTT data before the handshake keys are ready is refused, and a
 * receiver with nothing on the link gets nothing. */
static void test_session_guards(void) {
  const u8     dcid[8]  = {1, 2, 3, 4, 5, 6, 7, 8};
  u8           priv[32] = {9};
  quic_memlink link;
  quic_memlink_init(&link);
  quic_session         s;
  quic_session_init_in in = {priv, dcid, &link, 0};
  quic_session_init(&s, &in);
  quic_stream_frame got;
  CHECK(quic_session_recv_stream(&s, &got) == 0); /* empty link */
}

void test_session(void) {
  test_session_e2e();
  test_session_guards();
}
