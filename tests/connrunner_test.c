#include "test.h"
#include "connrunner/connrunner.h"
#include "connrunner/recv.h"
#include "connrunner/send.h"
#include "connrunner/level.h"
#include "frame/frame.h"
#include "frame/ack.h"

/* RFC 9000 17.2 / 17.3: byte0 -> protection level. Long-header Initial and
 * Handshake map to their keyset levels; a short header is 1-RTT; 0-RTT and
 * Retry are not driven by this loop. */
static void test_packet_level(void)
{
    int lv;
    CHECK(quic_connrunner_packet_level(0xc3, &lv) == 1
          && lv == QUIC_LEVEL_INITIAL);
    CHECK(quic_connrunner_packet_level(0xe3, &lv) == 1
          && lv == QUIC_LEVEL_HANDSHAKE);
    CHECK(quic_connrunner_packet_level(0x43, &lv) == 1
          && lv == QUIC_LEVEL_ONERTT);
    CHECK(quic_connrunner_packet_level(0xd3, &lv) == 0); /* 0-RTT */
    CHECK(quic_connrunner_packet_level(0xf3, &lv) == 0); /* Retry */
}

/* Install the same Initial keys on a connio pair and lift their gates so a
 * sealed packet from one opens under the other. */
static void arm(quic_connio *io)
{
    quic_initial_keys k = {0};
    io->loop.validated = 1;
    quic_keyset_install(&io->loop.keys, QUIC_LEVEL_INITIAL, &k);
}

static const u8 g_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

static void mk_runner(quic_connrunner *r, int is_server)
{
    quic_sockaddr_in peer = {0};
    quic_connrunner_init(r, -1, &peer, QUIC_LEVEL_INITIAL, 1u << 20, 64,
                         is_server, 0xc3, g_dcid, 8, 1u << 20);
    arm(&r->io);
    r->loop.gate.validated = 1; /* lift anti-amp on the loop side */
    quic_keyset_install(&r->loop.gate.keys, QUIC_LEVEL_INITIAL,
                        &(quic_initial_keys){0});
}

/* RFC 9001 5 / RFC 9000 13.2.1: a sealed ack-eliciting packet fed to
 * process_datagram is opened, dispatched, and queues an ack-eliciting receive
 * that owes an ACK once the loop steps. */
static void test_process_datagram_owes_ack(void)
{
    quic_connio cl;
    quic_connrunner r;
    quic_connio_init(&cl, 0, 0xc3, g_dcid, 8, 1u << 20);
    arm(&cl);
    mk_runner(&r, 1);

    u8 frames[64];
    quic_stream_frame sf = {.stream_id = 4, .offset = 0, .length = 5,
                            .data = (const u8 *)"hello", .fin = 1};
    usz fl = quic_frame_put_stream(frames, sizeof(frames), &sf);
    u8 pkt[256];
    usz n = quic_connio_send(&cl, QUIC_LEVEL_INITIAL, frames, fl,
                             pkt, sizeof(pkt));
    CHECK(n != 0);

    CHECK(quic_connrunner_process_datagram(&r, pkt, n) == 1);
    CHECK(r.loop.rx_n == 1);    /* queued into the loop */
    CHECK(r.loop.ack_owed == 0);/* not yet processed */
    quic_evloop_step(&r.loop, 0);
    CHECK(r.loop.ack_owed == 0);/* the same step's send carried the ACK */
    CHECK(r.loop.next_pn == 1); /* an ACK packet went out */
}

/* A non-ack-eliciting datagram (none accepted) owes no ACK. */
static void test_unparseable_owes_nothing(void)
{
    quic_connrunner r;
    mk_runner(&r, 1);
    u8 junk[32] = {0x43, 0, 0, 0}; /* short header, no valid keys/AEAD */
    quic_connrunner_process_datagram(&r, junk, sizeof(junk));
    quic_evloop_step(&r.loop, 0);
    CHECK(r.loop.ack_owed == 0);
    CHECK(r.loop.next_pn == 0); /* nothing to send */
}

/* RFC 9000 19.3: when the loop owes an ACK and steps to send it, flush_sends
 * builds and seals an ACK packet into txbuf. */
static void test_flush_sends_ack(void)
{
    quic_connrunner r;
    mk_runner(&r, 1);
    r.io.rx_pn = 3;          /* highest received = 2 */
    r.loop.ack_owed = 1;     /* an ACK is owed */

    int kind = quic_connrunner_pending_kind(&r);
    CHECK(kind == 1);        /* ACK has priority */
    u64 before = r.loop.next_pn;
    quic_evloop_step(&r.loop, 0);
    CHECK(r.loop.next_pn == before + 1); /* loop chose to send */
    usz out = quic_connrunner_flush_sends(&r, before, kind);
    CHECK(out != 0);         /* an ACK packet was sealed into txbuf */
}

/* RFC 9002 6: a queued retransmission is flushed as an ack-eliciting packet. */
static void test_flush_sends_retransmit(void)
{
    quic_connrunner r;
    mk_runner(&r, 1);
    r.loop.gate.handshake_complete = 1;
    r.loop.rtx_n = 1;
    r.loop.rtx[0].pn = 0;
    r.loop.rtx[0].len = 64;

    int kind = quic_connrunner_pending_kind(&r);
    CHECK(kind == 2);        /* retransmission */
    u64 before = r.loop.next_pn;
    quic_evloop_step(&r.loop, 0);
    usz out = quic_connrunner_flush_sends(&r, before, kind);
    CHECK(out != 0);         /* a packet was sealed */
}

/* RFC 9000 12: one advance runs recv before step before send. A sealed
 * ack-eliciting packet in, an ACK packet out, in a single call. */
static void test_advance_roundtrip(void)
{
    quic_connio cl;
    quic_connrunner r;
    quic_connio_init(&cl, 0, 0xc3, g_dcid, 8, 1u << 20);
    arm(&cl);
    mk_runner(&r, 1);

    u8 frames[8];
    usz fl = quic_frame_put_simple(frames, sizeof(frames), QUIC_FRAME_PING);
    u8 pkt[256];
    usz n = quic_connio_send(&cl, QUIC_LEVEL_INITIAL, frames, fl,
                             pkt, sizeof(pkt));
    CHECK(n != 0);

    usz out = quic_connrunner_advance(&r, 0, pkt, n);
    CHECK(out != 0);            /* the owed ACK was sealed and returned */
    CHECK(r.loop.next_pn == 1); /* exactly one send */
    CHECK(r.loop.ack_owed == 0);

    /* the sealed reply is a real ACK frame the peer can open */
    CHECK(quic_connio_recv(&cl, QUIC_LEVEL_INITIAL, r.txbuf, out) == 1);
}

/* RFC 9000 10.2: a closed connection does no further work in advance. */
static void test_advance_closed_idle(void)
{
    quic_connrunner r;
    mk_runner(&r, 1);
    quic_evloop_close(&r.loop, 0);
    usz out = quic_connrunner_advance(&r, 0, (u8 *)0, 0);
    CHECK(out == 0);
    CHECK(r.loop.next_pn == 0);
}

void test_connrunner(void)
{
    test_packet_level();
    test_process_datagram_owes_ack();
    test_unparseable_owes_nothing();
    test_flush_sends_ack();
    test_flush_sends_retransmit();
    test_advance_roundtrip();
    test_advance_closed_idle();
}
