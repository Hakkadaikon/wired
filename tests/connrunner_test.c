#include "test.h"
#include "connrunner/connrunner.h"
#include "connrunner/recv.h"
#include "connrunner/send.h"
#include "connrunner/level.h"
#include "connrunner/keyupdate.h"
#include "connrunner/reconnect.h"
#include "keyupdate/keyphase.h"
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

/* Drive one kind==2 retransmission and return the sealed datagram length. */
static usz drive_retransmit(quic_connrunner *r)
{
    int kind = quic_connrunner_pending_kind(r);
    u64 before = r->loop.next_pn;
    quic_connrunner_capture_rtx(r);
    quic_evloop_step(&r->loop, 0);
    return quic_connrunner_flush_sends(r, before, kind);
}

static void set_lost(quic_connrunner *r, u64 pn)
{
    r->loop.gate.handshake_complete = 1;
    r->loop.rtx_n = 1;
    r->loop.rtx[0].pn = pn;
}

/* RFC 9002 13.3: when the store holds the lost packet's frame bytes, the
 * retransmission carries those real frames -- not a one-byte PING stand-in.
 * A stored multi-byte frame seals a strictly larger datagram than the PING
 * fallback an empty store produces, proving the real bytes went on the wire. */
static void test_retransmit_real_bytes(void)
{
    quic_connrunner real, ping;
    mk_runner(&real, 1);
    mk_runner(&ping, 1);

    u8 frames[64];
    quic_stream_frame sf = {.stream_id = 4, .offset = 0, .length = 5,
                            .data = (const u8 *)"hello", .fin = 1};
    usz fl = quic_frame_put_stream(frames, sizeof(frames), &sf);
    CHECK(quic_rtxbytes_store(&real.rtx, 7, frames, fl) == 1);
    set_lost(&real, 7); /* held in the store -> real bytes */
    set_lost(&ping, 7); /* empty store -> PING fallback */

    usz real_out = drive_retransmit(&real);
    usz ping_out = drive_retransmit(&ping);
    CHECK(real_out != 0 && ping_out != 0);
    CHECK(real_out > ping_out); /* real frame bytes, not a 1-byte PING */
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

/* Seal an ACK whose Largest Acknowledged is `largest` from the peer connio. */
static usz seal_ack(quic_connio *peer, u64 largest, u8 *out, usz cap)
{
    u8 frames[32];
    quic_ack_frame f = {0};
    f.n_ranges = 1;
    f.ranges[0].hi = largest;
    f.ranges[0].lo = largest;
    usz fl = quic_ack_encode(frames, sizeof(frames), &f);
    CHECK(fl != 0 && frames[0] == 0x02); /* a real ACK frame was encoded */
    return quic_connio_send(peer, QUIC_LEVEL_INITIAL, frames, fl, out, cap);
}

/* RFC 9002 A.1 / 7.4: an in-flight send is recorded in the sentmeta ring and
 * adds its sealed bytes to total_in_flight over the real advance path; the
 * peer's ACK of that packet number drops it back out (A.2.2). */
static void test_sentmeta_inflight_tracking(void)
{
    quic_connio peer;
    quic_connrunner r;
    quic_connio_init(&peer, 0, 0xc3, g_dcid, 8, 1u << 20);
    arm(&peer);
    mk_runner(&r, 1);
    r.loop.gate.handshake_complete = 1;
    r.loop.have_new_data = 1; /* originate one in-flight packet */

    usz out = quic_connrunner_advance(&r, 1, (u8 *)0, 0);
    CHECK(out != 0);                       /* a packet went on the wire */
    CHECK(r.sent.total_in_flight == out);  /* its bytes are counted in flight */
    CHECK(quic_sentmeta_find(&r.sent, 0) != QUIC_SENTMETA_CAP); /* pn 0 tracked */

    r.loop.have_new_data = 0;
    u8 ack[256];
    usz an = seal_ack(&peer, 0, ack, sizeof(ack)); /* ACK Largest=0 */
    CHECK(an != 0);
    quic_connrunner_advance(&r, 2, ack, an);
    CHECK(r.io.disp.has_ack == 1);         /* the ACK was opened and dispatched */
    CHECK(r.sent.total_in_flight == 0);    /* acked -> dropped from in flight */
    CHECK(quic_sentmeta_find(&r.sent, 0) == QUIC_SENTMETA_CAP);
}

/* RFC 9002 6.1.1 / 13.3: a tracked packet kPacketThreshold below the largest
 * acked is declared lost and its pn is fed into the resend slot, so the next
 * flush retransmits it. */
static void test_sentmeta_loss_feeds_rtx(void)
{
    quic_connrunner r;
    mk_runner(&r, 1);
    /* seed the ring as if pns 0 and 3 are in flight, then ack only 3 */
    quic_sentmeta_on_sent(&r.sent, 0, 1, 1, 1, 64);
    quic_sentmeta_on_sent(&r.sent, 3, 1, 1, 1, 64);
    quic_sentmeta_find(&r.sent, 3); /* present */
    r.io.disp.has_ack = 1;
    r.io.disp.largest_acked = 3;

    r.rtx_held = 0;
    quic_connrunner_track_loss(&r, 1);
    CHECK(r.rtx_held == 1);  /* pn 0 is 3 below largest -> lost */
    CHECK(r.rtx_pn == 0);
    CHECK(quic_sentmeta_find(&r.sent, 0) == QUIC_SENTMETA_CAP); /* reclaimed */
}

/* A runner with a 1-RTT key installed and the key-update state seeded from it;
 * `confirmed` lifts the handshake-confirmed gate, `secret` makes derivation
 * produce distinct next-generation keys. */
static void mk_ku(quic_connrunner *r, int confirmed)
{
    mk_runner(r, 0);
    quic_keyset_install(&r->io.loop.keys, QUIC_LEVEL_ONERTT,
                        &(quic_initial_keys){0});
    r->io.loop.handshake_confirmed = confirmed;
    quic_connrunner_keyupdate_init(r);
    for (usz i = 0; i < QUIC_HKDF_PRK; i++) r->ku_secret[i] = (u8)(i + 1);
}

/* RFC 9001 6.2: a peer phase change before the handshake is confirmed must not
 * select the next generation's read key (counterexample the model forbids). */
static void test_ku_no_derive_before_confirm(void)
{
    quic_connrunner r;
    mk_ku(&r, 0);
    u8 byte0 = quic_keyphase_set(0x40, 1); /* opposite phase bit */
    CHECK(quic_connrunner_recv_keygen(&r, byte0) != 1); /* next NOT selected */
    CHECK(r.ku.generation == 0); /* send gen unchanged */
    CHECK(r.ku_phase == 0);      /* advertised phase unchanged */
}

/* RFC 9001 6.2: confirmed, a phase change selects the next generation's read
 * key; the current generation is still retained and send keys do not advance. */
static void test_ku_recv_selects_next_gen(void)
{
    quic_connrunner r;
    mk_ku(&r, 1);
    u8 byte0 = quic_keyphase_set(0x40, 1);
    CHECK(quic_connrunner_recv_keygen(&r, byte0) == 1); /* next generation */
    CHECK(r.ku.generation == 0);                        /* send gen unchanged */
}

/* RFC 9001 6.1: initiating derives and rotates keys, retains the old read key,
 * and toggles the phase bit -- send generation becomes 1, phase becomes 1. */
static void test_ku_initiate_derives_then_toggles(void)
{
    quic_connrunner r;
    mk_ku(&r, 1);
    r.ku_sent_in_phase = 100;
    CHECK(quic_connrunner_maybe_initiate_ku(&r, 100, 10, 1) == 1);
    CHECK(r.ku.generation == 1);
    CHECK(r.ku.have_old == 1);                  /* prior read key retained */
    CHECK(quic_keyphase_get(r.ku_phase) == 1);  /* phase == gen%2 */
    CHECK(r.ku_unacked == 1);
}

/* RFC 9001 6.1: an update is blocked before the handshake is confirmed. */
static void test_ku_initiate_blocked_before_confirm(void)
{
    quic_connrunner r;
    mk_ku(&r, 0);
    r.ku_sent_in_phase = 100;
    CHECK(quic_connrunner_maybe_initiate_ku(&r, 100, 10, 1) == 0);
    CHECK(r.ku.generation == 0);
}

/* RFC 9001 6.5: a second update is blocked while the first is unacknowledged. */
static void test_ku_initiate_blocked_until_acked(void)
{
    quic_connrunner r;
    mk_ku(&r, 1);
    r.ku_unacked = 1;            /* a self update still outstanding */
    r.ku_sent_in_phase = 100;
    CHECK(quic_connrunner_maybe_initiate_ku(&r, 100, 10, 1) == 0);
    CHECK(r.ku.generation == 0);
}

/* RFC 9001 6.5: a second update is blocked within 3*PTO of completion. */
static void test_ku_initiate_blocked_within_3pto(void)
{
    quic_connrunner r;
    mk_ku(&r, 1);
    r.ku_completed_at = 10;     /* completed at t=10, pto=2 -> floor at 16 */
    r.ku_sent_in_phase = 100;
    CHECK(quic_connrunner_maybe_initiate_ku(&r, 15, 10, 2) == 0); /* 15 < 16 */
    CHECK(quic_connrunner_maybe_initiate_ku(&r, 16, 10, 2) == 1); /* 16 >= 16 */
}

/* RFC 9001 6.5: the old read key is retained for the full 3*PTO window after
 * completion and discarded once it elapses. */
static void test_ku_discard_after_3pto(void)
{
    quic_connrunner r;
    mk_ku(&r, 1);
    r.ku_sent_in_phase = 100;
    quic_connrunner_maybe_initiate_ku(&r, 0, 10, 2);
    quic_connrunner_ku_completed(&r, 10);   /* completed at t=10 */
    CHECK(quic_connrunner_maybe_discard_ku(&r, 15, 2) == 0); /* 15 < 16 */
    CHECK(r.ku.have_old == 1);
    CHECK(quic_connrunner_maybe_discard_ku(&r, 16, 2) == 1); /* 16 >= 16 */
    CHECK(r.ku.have_old == 0);
}

/* RFC 9001 6.5: a packet requiring a discarded generation has no key (drop). */
static void test_ku_drop_discarded_gen(void)
{
    quic_connrunner r;
    mk_ku(&r, 1);
    r.ku_sent_in_phase = 100;
    quic_connrunner_maybe_initiate_ku(&r, 0, 10, 2); /* now at gen 1, phase 1 */
    quic_connrunner_ku_completed(&r, 0);
    quic_connrunner_maybe_discard_ku(&r, 100, 2);    /* drop the old gen-0 key */
    u8 old_phase = quic_keyphase_set(0x40, 0);       /* asks for gen 0 */
    CHECK(quic_connrunner_recv_keygen(&r, old_phase) == -1); /* no key */
}

/* RFC 9001 6.2: acknowledging a new-phase packet records the completion time
 * and pins both 3*PTO floors; only a self-initiated update is completed. */
static void test_ku_completion_records_time(void)
{
    quic_connrunner r;
    mk_ku(&r, 1);
    r.ku_unacked = 1;
    quic_connrunner_ku_completed(&r, 42);
    CHECK(r.ku_completed_at == 42);
    CHECK(r.ku_unacked == 0);
}

static void test_connrunner_keyupdate(void)
{
    test_ku_no_derive_before_confirm();
    test_ku_recv_selects_next_gen();
    test_ku_initiate_derives_then_toggles();
    test_ku_initiate_blocked_before_confirm();
    test_ku_initiate_blocked_until_acked();
    test_ku_initiate_blocked_within_3pto();
    test_ku_discard_after_3pto();
    test_ku_drop_discarded_gen();
    test_ku_completion_records_time();
}

static const u8 g_retry_scid[4] = {0xaa, 0xbb, 0xcc, 0xdd};
static const u8 g_retry_token[3] = {0x01, 0x02, 0x03};

/* RFC 9000 17.2.5.2: the first valid Retry is accepted, adopts the Retry SCID
 * as the new DCID, and marks the Initial keys stale (re-derivation pending). */
static void test_retry_first_accepted(void)
{
    quic_connrunner r;
    mk_runner(&r, 0);
    CHECK(quic_connrunner_recv_retry(&r, 1, g_retry_scid, 4,
                                     g_retry_token, 3) == 1);
    CHECK(r.retry.received == 1);
    CHECK(r.retry.dcid_len == 4 && r.retry.dcid[0] == 0xaa);
    CHECK(r.retry.key_rederive == 1);
}

/* RFC 9000 17.2.5.2: a Retry with an invalid Integrity Tag is discarded. */
static void test_retry_bad_tag_discarded(void)
{
    quic_connrunner r;
    mk_runner(&r, 0);
    CHECK(quic_connrunner_recv_retry(&r, 0, g_retry_scid, 4,
                                     g_retry_token, 3) == 0);
    CHECK(r.retry.received == 0);
}

/* RFC 9000 17.2.5.2: a second Retry is discarded (at most one per attempt). */
static void test_retry_second_discarded(void)
{
    quic_connrunner r;
    mk_runner(&r, 0);
    CHECK(quic_connrunner_recv_retry(&r, 1, g_retry_scid, 4,
                                     g_retry_token, 3) == 1);
    u8 other[4] = {0x11, 0x22, 0x33, 0x44};
    CHECK(quic_connrunner_recv_retry(&r, 1, other, 4, g_retry_token, 3) == 0);
    CHECK(r.retry.dcid[0] == 0xaa); /* DCID unchanged by the second Retry */
}

/* RFC 9001 5.2 / RFC 9000 17.2.5.1: the Initial after a Retry re-derives keys
 * for the new DCID before sending and carries the Retry token. */
static void test_retry_rederive_then_token(void)
{
    quic_connrunner r;
    mk_runner(&r, 0);
    quic_connrunner_recv_retry(&r, 1, g_retry_scid, 4, g_retry_token, 3);
    CHECK(quic_connrunner_retry_rederive(&r) == 1); /* keys re-derived first */
    CHECK(r.io.dcid_len == 4 && r.io.dcid[0] == 0xaa); /* DCID now the SCID */
    CHECK(r.retry.key_rederive == 0);                  /* no stale-key send */
    const u8 *tok;
    usz tlen;
    quic_connrunner_initial_token(&r, &tok, &tlen);
    CHECK(tlen == 3 && tok[0] == 0x01); /* the Retry token rides the Initial */
}

/* RFC 9000 17.2.5.2: a Retry arriving after the handshake progressed is
 * ignored and leaves the DCID unchanged. */
static void test_retry_ignored_after_progress(void)
{
    quic_connrunner r;
    mk_runner(&r, 0);
    r.io.loop.handshake_complete = 1; /* the handshake has progressed */
    CHECK(quic_connrunner_recv_retry(&r, 1, g_retry_scid, 4,
                                     g_retry_token, 3) == 0);
    CHECK(r.retry.received == 0);
}

static void test_connrunner_retry(void)
{
    test_retry_first_accepted();
    test_retry_bad_tag_discarded();
    test_retry_second_discarded();
    test_retry_rederive_then_token();
    test_retry_ignored_after_progress();
}

void test_connrunner(void)
{
    test_packet_level();
    test_process_datagram_owes_ack();
    test_unparseable_owes_nothing();
    test_flush_sends_ack();
    test_flush_sends_retransmit();
    test_retransmit_real_bytes();
    test_advance_roundtrip();
    test_advance_closed_idle();
    test_sentmeta_inflight_tracking();
    test_sentmeta_loss_feeds_rtx();
    test_connrunner_keyupdate();
    test_connrunner_retry();
}
