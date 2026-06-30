#include "test.h"
#include "connection/connection.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/handshake/core/tls/initial.h"
#include "frame/frame.h"

/* Install the same 1-RTT keys on both ends so a sealed packet opens. */
static void install_1rtt(quic_connection *c, const u8 dcid[8])
{
    quic_initial_keys k;
    quic_initial_derive(dcid, 8, 1, &k);
    quic_keyset_install(&c->keys, QUIC_LEVEL_ONERTT, &k);
}

/* client <-> server exchange a 1-RTT frame through the connection API. */
static void test_connection_roundtrip(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_memlink link; quic_memlink_init(&link);

    quic_connection cli, srv;
    quic_connection_init(&cli, dcid, &link, 0);
    quic_connection_init(&srv, dcid, &link, 1);
    install_1rtt(&cli, dcid);
    install_1rtt(&srv, dcid);

    u8 frames[16];
    quic_stream_frame sf = {.stream_id = 4, .offset = 0, .length = 5,
                            .data = (const u8 *)"hello", .fin = 1};
    usz fl = quic_frame_put_stream(frames, sizeof(frames), &sf);

    CHECK(quic_connection_send(&srv, QUIC_LEVEL_ONERTT, frames, fl) == 1);

    quic_framewalk it;
    CHECK(quic_connection_recv(&cli, QUIC_LEVEL_ONERTT, &it) == 1);

    u64 type; const u8 *start; usz rem;
    CHECK(quic_framewalk_next(&it, &type, &start, &rem) == 1);
    quic_stream_frame got;
    CHECK(quic_frame_get_stream(start, rem, &got) != 0);
    CHECK(got.stream_id == 4 && got.fin == 1 && got.length == 5);
    CHECK(got.data[0] == 'h' && got.data[4] == 'o');
}

/* Sending before keys are installed is refused; an empty link yields nothing. */
static void test_connection_guards(void)
{
    const u8 dcid[8] = {1,2,3,4,5,6,7,8};
    quic_memlink link; quic_memlink_init(&link);
    quic_connection c; quic_connection_init(&c, dcid, &link, 0);

    u8 frames[1] = {0x01}; /* PING */
    CHECK(quic_connection_send(&c, QUIC_LEVEL_ONERTT, frames, 1) == 0);

    quic_framewalk it;
    CHECK(quic_connection_recv(&c, QUIC_LEVEL_ONERTT, &it) == 0);
}

void test_connection(void)
{
    test_connection_roundtrip();
    test_connection_guards();
}
