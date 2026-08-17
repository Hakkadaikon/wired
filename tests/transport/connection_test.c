#include "transport/conn/lifecycle/connection/connection.h"

#include "crypto/kdf/keys/keyset.h"
#include "test.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/frame/frame/frame.h"

/* Install the same 1-RTT keys on both ends so a sealed packet opens. */
static void install_1rtt(connection* c, const u8 dcid[8]) {
  initial_keys k;
  initial_derive(wired_span_of(dcid, 8), 1, VERSION_1, &k);
  keyset_install(&c->keys, LEVEL_ONERTT, &k);
}

/* client <-> server exchange a 1-RTT frame through the connection API. */
static void test_connection_roundtrip(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  memlink  link;
  memlink_init(&link);

  connection         cli, srv;
  connection_init_in cin = {dcid, &link, 0};
  connection_init_in sin = {dcid, &link, 1};
  connection_init(&cli, &cin);
  connection_init(&srv, &sin);
  install_1rtt(&cli, dcid);
  install_1rtt(&srv, dcid);

  u8           frames[16];
  stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 5,
      .data      = (const u8*)"hello",
      .fin       = 1};
  usz fl = frame_put_stream(frames, sizeof(frames), &sf);

  CHECK(connection_send(&srv, LEVEL_ONERTT, wired_span_of(frames, fl)) == 1);

  framewalk it;
  CHECK(connection_recv(&cli, LEVEL_ONERTT, &it) == 1);

  framewalk_item fr;
  CHECK(framewalk_next(&it, &fr) == 1);
  stream_frame got;
  CHECK(frame_get_stream(fr.start, fr.remaining, &got) != 0);
  CHECK(got.stream_id == 4 && got.fin == 1 && got.length == 5);
  CHECK(got.data[0] == 'h' && got.data[4] == 'o');
}

/* Sending before keys are installed is refused; an empty link yields nothing.
 */
static void test_connection_guards(void) {
  const u8 dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  memlink  link;
  memlink_init(&link);
  connection         c;
  connection_init_in in = {dcid, &link, 0};
  connection_init(&c, &in);

  u8 frames[1] = {0x01}; /* PING */
  CHECK(connection_send(&c, LEVEL_ONERTT, wired_span_of(frames, 1)) == 0);

  framewalk it;
  CHECK(connection_recv(&c, LEVEL_ONERTT, &it) == 0);
}

void test_connection(void) {
  test_connection_roundtrip();
  test_connection_guards();
}
