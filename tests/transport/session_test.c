#include "transport/conn/lifecycle/session/session.h"

#include "test.h"
#include "transport/packet/frame/frame/frame.h"

/* A full kernel-free QUIC session: client and server complete a handshake
 * over the in-memory link and exchange 1-RTT STREAM data in both directions,
 * using only the high-level session API. */
static void test_session_e2e(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  u8       cpriv[32], spriv[32];
  for (usz i = 0; i < 32; i++) {
    cpriv[i] = (u8)(i + 1);
    spriv[i] = (u8)(0x40 + i);
  }

  memlink link;
  memlink_init(&link);

  session         cli, srv;
  session_init_in cin = {cpriv, dcid, &link, 0};
  session_init_in sin = {spriv, dcid, &link, 1};
  session_init(&cli, &cin);
  session_init(&srv, &sin);

  /* handshake: ClientHello over the link, server accepts, both agree keys */
  CHECK(session_client_hello(&cli) == 1);
  CHECK(session_accept(&srv) == 1);
  const u8 tr[] = "transcript";
  CHECK(session_finish(&cli, &srv, wired_span_of(tr, sizeof(tr))) == 1);

  /* server -> client 1-RTT STREAM */
  session_msg m1 = {4, {(const u8*)"hello", 5}, 1};
  CHECK(session_send_stream(&srv, &m1) == 1);
  stream_frame got;
  CHECK(session_recv_stream(&cli, &got) == 1);
  CHECK(got.stream_id == 4 && got.fin == 1 && got.length == 5);
  CHECK(got.data[0] == 'h' && got.data[4] == 'o');

  /* client -> server 1-RTT STREAM (reverse direction) */
  session_msg m2 = {0, {(const u8*)"hi!", 3}, 0};
  CHECK(session_send_stream(&cli, &m2) == 1);
  stream_frame got2;
  CHECK(session_recv_stream(&srv, &got2) == 1);
  CHECK(got2.stream_id == 0 && got2.length == 3);
  CHECK(got2.data[0] == 'h' && got2.data[2] == '!');
}

/* Sending 1-RTT data before the handshake keys are ready is refused, and a
 * receiver with nothing on the link gets nothing. */
static void test_session_guards(void) {
  const u8 dcid[8]  = {1, 2, 3, 4, 5, 6, 7, 8};
  u8       priv[32] = {9};
  memlink  link;
  memlink_init(&link);
  session         s;
  session_init_in in = {priv, dcid, &link, 0};
  session_init(&s, &in);
  stream_frame got;
  CHECK(session_recv_stream(&s, &got) == 0); /* empty link */
}

/* A frame shorter than the 20-byte IPv4 header is dropped before any
 * header read: frame.n - 20 must not underflow into a huge UDP span. */
static void test_session_rejects_short_frame(void) {
  const u8 dcid[8]  = {1, 2, 3, 4, 5, 6, 7, 8};
  u8       priv[32] = {9};
  u8       shortf[19];
  memlink  link;
  memlink_init(&link);
  session         s;
  session_init_in in = {priv, dcid, &link, 0};
  session_init(&s, &in);
  for (usz i = 0; i < sizeof shortf; i++) {
    shortf[i] = 0;
  }
  shortf[0] = 0x45;
  memlink_send(&link, shortf, sizeof shortf);
  stream_frame got;
  CHECK(session_recv_stream(&s, &got) == 0);
}

/* A client/server pair on one link, keyed like test_session_e2e. */
static void sess_pair(memlink* link, session* cli, session* srv) {
  static const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  u8              cpriv[32], spriv[32];
  for (usz i = 0; i < 32; i++) {
    cpriv[i] = (u8)(i + 1);
    spriv[i] = (u8)(0x40 + i);
  }
  memlink_init(link);
  session_init_in cin = {cpriv, dcid, link, 0};
  session_init_in sin = {spriv, dcid, link, 1};
  session_init(cli, &cin);
  session_init(srv, &sin);
}

/* Client sends an Initial carrying payload under the Initial keys. */
static int sess_send_initial(session* cli, wired_span payload) {
  protect_keys k = {&cli->ikeys, &cli->ihp};
  return session_seal_tx(
      cli, &k, 0xc3, 1, payload, (ipv4addrs){SESSION_CA, SESSION_SA});
}

/* RFC 9000 17.2.2: the server's accept needs a CRYPTO frame carrying a
 * well-formed handshake message; anything else yields no peer share. */
static void test_session_accept_rejects(void) {
  static const u8 ping[]    = {0x01};
  static const u8 trunc[]   = {0x06, 0x00, 0x01, 0x01}; /* CRYPTO, 1-byte hs */
  static u8       big[1200] = {0};
  memlink         link;
  session         cli, srv;
  sess_pair(&link, &cli, &srv);
  CHECK(session_accept(&srv) == 0); /* empty link */
  CHECK(sess_send_initial(&cli, wired_span_of(ping, 1)) == 1);
  CHECK(session_accept(&srv) == 0); /* no CRYPTO frame */
  CHECK(sess_send_initial(&cli, wired_span_of(trunc, sizeof trunc)) == 1);
  CHECK(session_accept(&srv) == 0); /* truncated handshake header */
  CHECK(sess_send_initial(&cli, wired_span_of(big, sizeof big)) == 0);
  CHECK(srv.have_peer == 0);
}

/* RFC 7748 6.1: finish before any peer share, or with a low-order (all-zero)
 * client share, aborts the key agreement. */
static void test_session_finish_rejects(void) {
  static const u8 tr[] = "transcript";
  memlink         link;
  session         cli, srv;
  sess_pair(&link, &cli, &srv);
  CHECK(session_finish(&cli, &srv, wired_span_of(tr, sizeof tr)) == 0);
  bytes_memset(cli.ep.pub, 0, sizeof cli.ep.pub);
  CHECK(session_client_hello(&cli) == 1);
  CHECK(session_accept(&srv) == 1);
  CHECK(session_finish(&cli, &srv, wired_span_of(tr, sizeof tr)) == 0);
}

void test_session(void) {
  test_session_e2e();
  test_session_guards();
  test_session_rejects_short_frame();
  test_session_accept_rejects();
  test_session_finish_rejects();
}
