#include "test.h"
#include "connio/connio.h"
#include "frame/frame.h"

/* RFC 9001 5: a STREAM frame sealed by one peer's connio_send opens under the
 * other peer's connio_recv (same installed keys) and lands in stream_read. */
static void test_connio_seal_open_roundtrip(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_connio cl, sv;
    quic_connio_init(&cl, 0, 0x43, dcid, 8, 1u << 20);
    quic_connio_init(&sv, 1, 0x43, dcid, 8, 1u << 20);
    cl.loop.validated = 1;
    sv.loop.validated = 1;
    quic_initial_keys k = {0};
    quic_keyset_install(&cl.loop.keys, QUIC_LEVEL_INITIAL, &k);
    quic_keyset_install(&sv.loop.keys, QUIC_LEVEL_INITIAL, &k);

    u8 frames[64];
    quic_stream_frame sf = {.stream_id = 4, .offset = 0, .length = 5,
                            .data = (const u8 *)"hello", .fin = 1};
    usz fl = quic_frame_put_stream(frames, sizeof(frames), &sf);
    CHECK(fl != 0);

    u8 pkt[256];
    usz pn = quic_connio_send(&cl, QUIC_LEVEL_INITIAL, frames, fl,
                              pkt, sizeof(pkt));
    CHECK(pn != 0);

    CHECK(quic_connio_recv(&sv, QUIC_LEVEL_INITIAL, pkt, pn) == 1);

    /* the STREAM bytes reached the server's read buffer in order */
    u8 got[16];
    usz got_len = 0;
    quic_stream_read_pull(&sv.stream, got, sizeof(got), &got_len);
    CHECK(got_len == 5);
    CHECK(got[0] == 'h' && got[4] == 'o');
}

/* RFC 9001 4: with no key installed at a level, both send and recv are gated
 * out (return 0) before any cryptographic work. */
static void test_connio_gated_without_key(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_connio io;
    quic_connio_init(&io, 0, 0x43, dcid, 8, 1u << 20);
    io.loop.validated = 1;

    u8 frames[8] = {0x01}; /* a PING frame */
    u8 pkt[64];
    /* Handshake level has no key installed */
    CHECK(quic_connio_send(&io, QUIC_LEVEL_HANDSHAKE, frames, 1,
                           pkt, sizeof(pkt)) == 0);
    CHECK(quic_connio_recv(&io, QUIC_LEVEL_HANDSHAKE, pkt, 32) == 0);
}

void test_connio(void)
{
    test_connio_seal_open_roundtrip();
    test_connio_gated_without_key();
}
