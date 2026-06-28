#include "test.h"
#include "pipeline/txpacket.h"
#include "pipeline/rxpacket.h"
#include "tls/initial.h"
#include "frame/frame.h"

/* RFC 9001 5: rx recovers the exact multi-frame payload that tx sealed. */
static void test_rxpacket_payload_view(void)
{
    const u8 dcid[8] = {9,8,7,6,5,4,3,2};
    quic_initial_keys ik;
    quic_aes128 hp;
    quic_initial_derive(dcid, 8, 1, &ik);
    quic_aes128_init(&hp, ik.hp);

    u8 frames[8];
    usz fl = 0;
    fl += quic_frame_put_simple(frames + fl, sizeof(frames) - fl, QUIC_FRAME_PING);
    fl += quic_frame_put_simple(frames + fl, sizeof(frames) - fl, QUIC_FRAME_PADDING);
    fl += quic_frame_put_simple(frames + fl, sizeof(frames) - fl, QUIC_FRAME_PING);
    CHECK(fl == 3);

    u8 pkt[256];
    usz n = quic_tx_packet(&ik, &hp, 0xc3, dcid, 8, 5, frames, fl, pkt, sizeof(pkt));
    CHECK(n != 0);

    const u8 *got;
    usz got_len;
    CHECK(quic_rx_packet(&ik, &hp, pkt, n, 8, 5, &got, &got_len) == 1);
    CHECK(got_len == 3);
    CHECK(got[0] == QUIC_FRAME_PING && got[1] == QUIC_FRAME_PADDING);
    CHECK(got[2] == QUIC_FRAME_PING);
}

/* A packet shorter than its header is rejected. */
static void test_rxpacket_too_short(void)
{
    quic_initial_keys ik;
    quic_aes128 hp;
    u8 buf[4] = {0};
    const u8 *got;
    usz got_len;
    CHECK(quic_rx_packet(&ik, &hp, buf, sizeof(buf), 8, 1, &got, &got_len) == 0);
}

void test_rxpacket(void)
{
    test_rxpacket_payload_view();
    test_rxpacket_too_short();
}
