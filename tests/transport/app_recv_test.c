#include "test.h"

static void recv_keys(quic_initial_keys *k, quic_aes128 *hp)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_initial_derive(dcid, 8, 1, k);
    quic_aes128_init(hp, k->hp);
}

/* RFC 9001 5: a 1-RTT packet sealed with one app key does not open under a
 * different dcid_len (header recovery / AEAD nonce mismatch). */
static void test_recv_wrong_dcidlen(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[5] = {1,2,3,4,5};
    const u8 body[] = {'z'};
    recv_keys(&k, &hp);

    u8 pkt[128];
    usz total = 0;
    CHECK(quic_appdata_send(&k, &hp, dcid, 5, 1, 8, body, sizeof(body), 0,
                            pkt, sizeof(pkt), &total));

    u64 sid = 0, off = 0;
    const u8 *data = 0;
    usz dlen = 0;
    int fin = 0;
    CHECK(!quic_appdata_recv(&k, &hp, pkt, total, 4,
                             &sid, &off, &data, &dlen, &fin));
}

/* RFC 9000 19.8: nonzero send offset is recovered by recv. */
static void test_recv_offset(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {7,7,7,7};
    const u8 body[] = {'p','q'};
    recv_keys(&k, &hp);

    /* build a STREAM frame with offset directly, seal it, then recv. */
    u8 frame[32];
    usz flen = 0;
    CHECK(quic_appdata_stream_frame(12, 256, body, sizeof(body), 0,
                                    frame, sizeof(frame), &flen));
    u8 pkt[128];
    usz total = 0;
    CHECK(quic_hspkt_onertt_build(&k, &hp, dcid, 4, 3, frame, flen,
                                  pkt, sizeof(pkt), &total));

    u64 sid = 0, off = 0;
    const u8 *data = 0;
    usz dlen = 0;
    int fin = 1;
    CHECK(quic_appdata_recv(&k, &hp, pkt, total, 4,
                            &sid, &off, &data, &dlen, &fin));
    CHECK(sid == 12);
    CHECK(off == 256);
    CHECK(fin == 0);
    CHECK(dlen == sizeof(body));
    CHECK(data[0] == 'p' && data[1] == 'q');
}

/* RFC 9001 5: a 1-RTT packet that opens to an empty payload must not be
 * decoded as a STREAM frame (no out-of-bounds read of the type byte). */
static void test_recv_empty_payload(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {4,4,4,4};
    recv_keys(&k, &hp);

    u8 pkt[128];
    usz total = 0;
    CHECK(quic_hspkt_onertt_build(&k, &hp, dcid, 4, 1, (const u8 *)"", 0,
                                  pkt, sizeof(pkt), &total));

    u64 sid = 0, off = 0;
    const u8 *data = 0;
    usz dlen = 0;
    int fin = 0;
    CHECK(!quic_appdata_recv(&k, &hp, pkt, total, 4,
                             &sid, &off, &data, &dlen, &fin));
}

/* RFC 9000 19.8: a STREAM frame whose Length varint runs past the payload is
 * malformed; recv returns 0. */
static void test_recv_malformed(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {5,5,5,5};
    recv_keys(&k, &hp);

    /* type 0x0a (STREAM|LEN), stream_id 0, Length=10 but no data bytes. */
    const u8 bad[] = {0x0a, 0x00, 0x0a};
    u8 pkt[128];
    usz total = 0;
    CHECK(quic_hspkt_onertt_build(&k, &hp, dcid, 4, 2, bad, sizeof(bad),
                                  pkt, sizeof(pkt), &total));

    u64 sid = 0, off = 0;
    const u8 *data = 0;
    usz dlen = 0;
    int fin = 0;
    CHECK(!quic_appdata_recv(&k, &hp, pkt, total, 4,
                             &sid, &off, &data, &dlen, &fin));
}

/* RFC 9000 16/19.8: a stream id needing a 2-byte varint (0x3fff) round-trips
 * through the 1-RTT path. */
static void test_recv_large_stream_id(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {6,6,6,6};
    const u8 body[] = {'k'};
    recv_keys(&k, &hp);

    u8 pkt[128];
    usz total = 0;
    CHECK(quic_appdata_send(&k, &hp, dcid, 4, 9, 0x3fff, body, sizeof(body), 0,
                            pkt, sizeof(pkt), &total));

    u64 sid = 0, off = 0;
    const u8 *data = 0;
    usz dlen = 0;
    int fin = 0;
    CHECK(quic_appdata_recv(&k, &hp, pkt, total, 4,
                            &sid, &off, &data, &dlen, &fin));
    CHECK(sid == 0x3fff);
    CHECK(data[0] == 'k');
}

void test_app_recv(void)
{
    test_recv_wrong_dcidlen();
    test_recv_offset();
    test_recv_empty_payload();
    test_recv_malformed();
    test_recv_large_stream_id();
}
