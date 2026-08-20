#include "transport/conn/loop/connrunner/connrunner.h"

#include "test.h"
#include "tls/keys/keyupdate/aeadintegrity.h"
#include "tls/keys/keyupdate/keyphase.h"
#include "tls/keys/kuswitch/derive.h"
#include "transport/conn/loop/connrunner/keyupdate.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/conn/loop/connrunner/reconnect.h"
#include "transport/conn/loop/connrunner/recv.h"
#include "transport/conn/loop/connrunner/send.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"
#include "transport/version/version/version.h"

/* RFC 9000 17.2 / 17.3: byte0 -> protection level. Long-header Initial and
 * Handshake map to their keyset levels; a short header is 1-RTT; 0-RTT and
 * Retry are not driven by this loop. */
static void test_packet_level(void) {
  int lv;
  CHECK(connrunner_packet_level(0xc3, &lv) == 1 && lv == LEVEL_INITIAL);
  CHECK(connrunner_packet_level(0xe3, &lv) == 1 && lv == LEVEL_HANDSHAKE);
  CHECK(connrunner_packet_level(0x43, &lv) == 1 && lv == LEVEL_ONERTT);
  CHECK(connrunner_packet_level(0xd3, &lv) == 0); /* 0-RTT */
  CHECK(connrunner_packet_level(0xf3, &lv) == 0); /* Retry */
}

/* Install the same Initial keys on a connio pair and lift their gates so a
 * sealed packet from one opens under the other. */
static void arm(connio* io) {
  initial_keys k     = {0};
  io->loop.validated = 1;
  keyset_install(&io->loop.keys, LEVEL_INITIAL, &k);
}

static const u8 g_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

static void mk_runner(connrunner* r, int is_server) {
  sockaddr           peer = {0};
  connrunner_init_in in   = {-1, &peer,     LEVEL_INITIAL, 1u << 20,
                             64, is_server, 0xc3,          1u << 20};
  connrunner_init(r, wired_span_of(g_dcid, 8), &in);
  arm(&r->io);
  r->loop.gate.validated = 1; /* lift anti-amp on the loop side */
  keyset_install(&r->loop.gate.keys, LEVEL_INITIAL, &(initial_keys){0});
}

/* RFC 9001 5 / RFC 9000 13.2.1: a sealed ack-eliciting packet fed to
 * process_datagram is opened, dispatched, and queues an ack-eliciting receive
 * that owes an ACK once the loop steps. */
static void test_process_datagram_owes_ack(void) {
  connio         cl;
  connrunner     r;
  connio_init_in cin = {0, 0xc3, 1u << 20};
  connio_init(&cl, wired_span_of(g_dcid, 8), &cin);
  arm(&cl);
  mk_runner(&r, 1);

  u8           frames[64];
  stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 5,
      .data      = (const u8*)"hello",
      .fin       = 1};
  usz fl = frame_put_stream(frames, sizeof(frames), &sf);
  u8  pkt[256];
  usz n;
  {
    connio_send_in sin = {LEVEL_INITIAL, wired_span_of(frames, fl)};
    wired_obuf     ob  = obuf_of(pkt, sizeof(pkt));
    n                  = connio_send(&cl, &sin, &ob);
  }
  CHECK(n != 0);

  CHECK(connrunner_process_datagram(&r, wired_mspan_of(pkt, n)) == 1);
  CHECK(r.loop.rx_n == 1);     /* queued into the loop */
  CHECK(r.loop.ack_owed == 0); /* not yet processed */
  evloop_step(&r.loop, 0);
  CHECK(r.loop.ack_owed == 0); /* the same step's send carried the ACK */
  CHECK(r.loop.next_pn == 1);  /* an ACK packet went out */
}

/* RFC 9000 12.2: a coalesced/received packet whose Destination Connection ID
 * differs from the connection's own is ignored, not processed under the
 * wrong connection's state. Flipping one byte of the sealed long-header
 * packet's DCID (offset 6, after byte0+version+dcid_len) makes an otherwise
 * valid packet unaccepted. */
static void test_process_datagram_dcid_mismatch_ignored(void) {
  connio         cl;
  connrunner     r;
  connio_init_in cin = {0, 0xc3, 1u << 20};
  connio_init(&cl, wired_span_of(g_dcid, 8), &cin);
  arm(&cl);
  mk_runner(&r, 1);

  u8           frames[64];
  stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 5,
      .data      = (const u8*)"hello",
      .fin       = 1};
  usz fl = frame_put_stream(frames, sizeof(frames), &sf);
  u8  pkt[256];
  usz n;
  {
    connio_send_in sin = {LEVEL_INITIAL, wired_span_of(frames, fl)};
    wired_obuf     ob  = obuf_of(pkt, sizeof(pkt));
    n                  = connio_send(&cl, &sin, &ob);
  }
  CHECK(n != 0);
  pkt[6] ^= 0xff; /* corrupt the first DCID byte (long header, offset 6) */

  CHECK(connrunner_process_datagram(&r, wired_mspan_of(pkt, n)) == 0);
  CHECK(r.loop.rx_n == 0); /* never reached dispatch */
}

/* A non-ack-eliciting datagram (none accepted) owes no ACK. */
static void test_unparseable_owes_nothing(void) {
  connrunner r;
  mk_runner(&r, 1);
  u8 junk[32] = {0x43, 0, 0, 0}; /* short header, no valid keys/AEAD */
  connrunner_process_datagram(&r, wired_mspan_of(junk, sizeof(junk)));
  evloop_step(&r.loop, 0);
  CHECK(r.loop.ack_owed == 0);
  CHECK(r.loop.next_pn == 0); /* nothing to send */
}

/* RFC 9000 19.3: when the loop owes an ACK and steps to send it, flush_sends
 * builds and seals an ACK packet into txbuf. */
static void test_flush_sends_ack(void) {
  connrunner r;
  mk_runner(&r, 1);
  r.io.rx_pn[LEVEL_INITIAL] = 3; /* highest received = 2 */
  r.loop.ack_owed           = 1; /* an ACK is owed */

  int kind = connrunner_pending_kind(&r);
  CHECK(kind == 1); /* ACK has priority */
  u64 before = r.loop.next_pn;
  evloop_step(&r.loop, 0);
  CHECK(r.loop.next_pn == before + 1); /* loop chose to send */
  usz out = connrunner_flush_sends(&r, before, kind);
  CHECK(out != 0); /* an ACK packet was sealed into txbuf */
}

/* RFC 9002 6: a queued retransmission is flushed as an ack-eliciting packet. */
static void test_flush_sends_retransmit(void) {
  connrunner r;
  mk_runner(&r, 1);
  r.loop.gate.handshake_complete = 1;
  r.loop.rtx_n                   = 1;
  r.loop.rtx[0].pn               = 0;
  r.loop.rtx[0].len              = 64;

  int kind = connrunner_pending_kind(&r);
  CHECK(kind == 2); /* retransmission */
  u64 before = r.loop.next_pn;
  evloop_step(&r.loop, 0);
  usz out = connrunner_flush_sends(&r, before, kind);
  CHECK(out != 0); /* a packet was sealed */
}

/* Drive one kind==2 retransmission and return the sealed datagram length. */
static usz drive_retransmit(connrunner* r) {
  int kind   = connrunner_pending_kind(r);
  u64 before = r->loop.next_pn;
  connrunner_capture_rtx(r);
  evloop_step(&r->loop, 0);
  return connrunner_flush_sends(r, before, kind);
}

static void set_lost(connrunner* r, u64 pn) {
  r->loop.gate.handshake_complete = 1;
  r->loop.rtx_n                   = 1;
  r->loop.rtx[0].pn               = pn;
}

/* RFC 9002 13.3: when the store holds the lost packet's frame bytes, the
 * retransmission carries those real frames -- not a one-byte PING stand-in.
 * A stored multi-byte frame seals a strictly larger datagram than the PING
 * fallback an empty store produces, proving the real bytes went on the wire. */
static void test_retransmit_real_bytes(void) {
  connrunner real, ping;
  mk_runner(&real, 1);
  mk_runner(&ping, 1);

  u8           frames[64];
  stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 5,
      .data      = (const u8*)"hello",
      .fin       = 1};
  usz fl = frame_put_stream(frames, sizeof(frames), &sf);
  CHECK(rtxbytes_store(&real.rtx, 7, wired_span_of(frames, fl)) == 1);
  set_lost(&real, 7); /* held in the store -> real bytes */
  set_lost(&ping, 7); /* empty store -> PING fallback */

  usz real_out = drive_retransmit(&real);
  usz ping_out = drive_retransmit(&ping);
  CHECK(real_out != 0 && ping_out != 0);
  CHECK(real_out > ping_out); /* real frame bytes, not a 1-byte PING */
}

/* RFC 9000 12: one advance runs recv before step before send. A sealed
 * ack-eliciting packet in, an ACK packet out, in a single call. */
static void test_advance_roundtrip(void) {
  connio         cl;
  connrunner     r;
  connio_init_in cin = {0, 0xc3, 1u << 20};
  connio_init(&cl, wired_span_of(g_dcid, 8), &cin);
  arm(&cl);
  mk_runner(&r, 1);

  u8  frames[8];
  usz fl = frame_put_simple(frames, sizeof(frames), FRAME_PING);
  u8  pkt[256];
  usz n;
  {
    connio_send_in sin = {LEVEL_INITIAL, wired_span_of(frames, fl)};
    wired_obuf     ob  = obuf_of(pkt, sizeof(pkt));
    n                  = connio_send(&cl, &sin, &ob);
  }
  CHECK(n != 0);

  usz out = connrunner_advance(&r, 0, wired_mspan_of(pkt, n));
  CHECK(out != 0);            /* the owed ACK was sealed and returned */
  CHECK(r.loop.next_pn == 1); /* exactly one send */
  CHECK(r.loop.ack_owed == 0);

  /* the sealed reply is a real ACK frame the peer can open */
  CHECK(connio_recv(&cl, LEVEL_INITIAL, wired_mspan_of(r.txbuf, out)) == 1);
}

/* RFC 9000 10.2: a closed connection does no further work in advance. */
static void test_advance_closed_idle(void) {
  connrunner r;
  mk_runner(&r, 1);
  evloop_close(&r.loop, 0);
  usz out = connrunner_advance(&r, 0, wired_mspan_of((u8*)0, 0));
  CHECK(out == 0);
  CHECK(r.loop.next_pn == 0);
}

/* Install a 1-RTT key on io and fast-forward its send-level gate to
 * Handshake, so the next send may promote straight to 1-RTT (RFC 9001
 * 4.1.4/4.9) -- same shape as connio_test.c's own connrunner_arm_onertt. */
static void connrunner_arm_onertt(connio* io) {
  initial_keys k     = {0};
  io->loop.validated = 1;
  keyset_install(&io->loop.keys, LEVEL_INITIAL, &k);
  keyset_install(&io->loop.keys, LEVEL_HANDSHAKE, &k);
  keyset_install(&io->loop.keys, LEVEL_ONERTT, &k);
  io->loop.send_level         = LEVEL_HANDSHAKE;
  io->loop.handshake_complete = 1;
}

/* RFC 9000 19.20 via 12.4: a server connrunner that receives HANDSHAKE_DONE
 * (forbidden on a server's receive side) must answer with a transport
 * CONNECTION_CLOSE(PROTOCOL_VIOLATION) on its very next advance, even though
 * the loop itself has nothing else queued to send -- connio_recv latches
 * io.disp.violation and connrunner_advance must wire
 * connio_close_on_violation into its own send path to act on it
 * (RFC 9000 10.2), not just leave the flag set. */
static void test_advance_closes_on_violation(void) {
  connio     cl;
  connrunner r;
  mk_runner(&r, 1); /* server */
  connio_init_in cin = {0, 0x43, 1u << 20};
  connio_init(&cl, wired_span_of(g_dcid, 8), &cin);
  connrunner_arm_onertt(&cl);
  connrunner_arm_onertt(&r.io);

  u8  frame[1] = {0};
  usz fl       = handshake_done_encode(frame, sizeof frame);
  CHECK(fl != 0);
  u8  pkt[256];
  usz n;
  {
    connio_send_in sin = {LEVEL_ONERTT, wired_span_of(frame, fl)};
    wired_obuf     ob  = obuf_of(pkt, sizeof pkt);
    n                  = connio_send(&cl, &sin, &ob);
  }
  CHECK(n != 0);

  {
    usz out = connrunner_advance(&r, 0, wired_mspan_of(pkt, n));
    CHECK(out != 0); /* a CONNECTION_CLOSE was sealed, not silence */
    CHECK(r.io.disp.violation == 0); /* the flag fired and was cleared */

    /* the client's own connio opens it and sees a real transport close */
    CHECK(connio_recv(&cl, LEVEL_ONERTT, wired_mspan_of(r.txbuf, out)) == 1);
    CHECK(cl.disp.close == 1);
  }
}

/* RFC 9001 6.6: same shape as test_advance_closes_on_violation, but for the
 * AEAD integrity limit -- connrunner_advance must wire
 * connio_close_on_aead_limit into its own send path too, not just
 * close_on_violation, so a server whose auth_fail_count has reached the
 * AES-GCM limit answers with CONNECTION_CLOSE(AEAD_LIMIT_REACHED) on its very
 * next advance even with nothing else queued to send. */
static void test_advance_closes_on_aead_limit(void) {
  connio     cl;
  connrunner r;
  mk_runner(&r, 1); /* server */
  connio_init_in cin = {0, 0x43, 1u << 20};
  connio_init(&cl, wired_span_of(g_dcid, 8), &cin);
  connrunner_arm_onertt(&cl);
  connrunner_arm_onertt(&r.io);
  r.io.loop.auth_fail_count = AEAD_INTEGRITY_LIMIT_AESGCM - 1;

  u8  frame[1] = {0x01}; /* PING, ack-eliciting */
  u8  pkt[256];
  usz pn;
  {
    connio_send_in sin = {LEVEL_ONERTT, wired_span_of(frame, 1)};
    wired_obuf     ob  = obuf_of(pkt, sizeof pkt);
    pn                 = connio_send(&cl, &sin, &ob);
  }
  CHECK(pn != 0);
  pkt[pn - 1] ^= 0xff; /* tamper the AEAD tag so recv fails auth */

  {
    usz out = connrunner_advance(&r, 0, wired_mspan_of(pkt, pn));
    CHECK(out != 0); /* a CONNECTION_CLOSE was sealed, not silence */
    CHECK(r.io.loop.aead_limit == 0); /* the flag fired and was cleared */

    CHECK(connio_recv(&cl, LEVEL_ONERTT, wired_mspan_of(r.txbuf, out)) == 1);
    CHECK(cl.disp.close == 1);
  }
}

/* RFC 9000 3.5: same shape as test_advance_closes_on_violation, but for
 * STOP_SENDING -- connrunner_advance must wire
 * connio_send_stop_sending_reset into its own send path too, so a
 * server that received STOP_SENDING answers with the obligated RESET_STREAM
 * on its very next advance even with nothing else queued to send. */
static void test_advance_sends_stop_sending_reset(void) {
  connio     cl;
  connrunner r;
  mk_runner(&r, 1); /* server */
  connio_init_in cin = {0, 0x43, 1u << 20};
  connio_init(&cl, wired_span_of(g_dcid, 8), &cin);
  connrunner_arm_onertt(&cl);
  connrunner_arm_onertt(&r.io);

  stop_sending_frame ssf = {.stream_id = 5, .error_code = 0x77};
  u8                 frame[16];
  usz                fl = stop_sending_encode(frame, sizeof frame, &ssf);
  CHECK(fl != 0);
  u8  pkt[256];
  usz pn;
  {
    connio_send_in sin = {LEVEL_ONERTT, wired_span_of(frame, fl)};
    wired_obuf     ob  = obuf_of(pkt, sizeof pkt);
    pn                 = connio_send(&cl, &sin, &ob);
  }
  CHECK(pn != 0);

  {
    usz out = connrunner_advance(&r, 0, wired_mspan_of(pkt, pn));
    CHECK(out != 0); /* a RESET_STREAM was sealed, not silence */
    CHECK(r.io.disp.stop_sending_owed == 0); /* the flag fired and cleared */

    CHECK(connio_recv(&cl, LEVEL_ONERTT, wired_mspan_of(r.txbuf, out)) == 1);
    CHECK(
        cl.disp.reset_stream_stream_id == 5 &&
        cl.disp.reset_stream_error_code == 0x77);
  }
}

/* Seal an ACK whose Largest Acknowledged is `largest` from the peer connio. */
static usz seal_ack(connio* peer, u64 largest, u8* out, usz cap) {
  u8        frames[32];
  ack_frame f    = {0};
  f.n_ranges     = 1;
  f.ranges[0].hi = largest;
  f.ranges[0].lo = largest;
  usz fl         = ack_encode(frames, sizeof(frames), &f);
  CHECK(fl != 0 && frames[0] == 0x02); /* a real ACK frame was encoded */
  {
    connio_send_in sin = {LEVEL_INITIAL, wired_span_of(frames, fl)};
    wired_obuf     ob  = obuf_of(out, cap);
    return connio_send(peer, &sin, &ob);
  }
}

/* RFC 9002 A.1 / 7.4: an in-flight send is recorded in the sentmeta ring and
 * adds its sealed bytes to total_in_flight over the real advance path; the
 * peer's ACK of that packet number drops it back out (A.2.2). */
static void test_sentmeta_inflight_tracking(void) {
  connio         peer;
  connrunner     r;
  connio_init_in cin = {0, 0xc3, 1u << 20};
  connio_init(&peer, wired_span_of(g_dcid, 8), &cin);
  arm(&peer);
  mk_runner(&r, 1);
  r.loop.gate.handshake_complete = 1;
  r.loop.have_new_data           = 1; /* originate one in-flight packet */

  usz out = connrunner_advance(&r, 1, wired_mspan_of((u8*)0, 0));
  CHECK(out != 0);                      /* a packet went on the wire */
  CHECK(r.sent.total_in_flight == out); /* its bytes are counted in flight */
  CHECK(sentmeta_find(&r.sent, 0) != SENTMETA_CAP); /* pn 0 tracked */

  r.loop.have_new_data = 0;
  u8  ack[256];
  usz an = seal_ack(&peer, 0, ack, sizeof(ack)); /* ACK Largest=0 */
  CHECK(an != 0);
  connrunner_advance(&r, 2, wired_mspan_of(ack, an));
  CHECK(r.io.disp.has_ack == 1);      /* the ACK was opened and dispatched */
  CHECK(r.sent.total_in_flight == 0); /* acked -> dropped from in flight */
  CHECK(sentmeta_find(&r.sent, 0) == SENTMETA_CAP);
}

/* RFC 9002 6.1.1 / 13.3: a tracked packet kPacketThreshold below the largest
 * acked is declared lost and its pn is fed into the resend slot, so the next
 * flush retransmits it. */
static void test_sentmeta_loss_feeds_rtx(void) {
  connrunner r;
  mk_runner(&r, 1);
  /* seed the ring as if pns 0 and 3 are in flight, then ack only 3 */
  sentmeta_on_sent(&r.sent, &(sentmeta_out){0, 1, 1, 1, 64});
  sentmeta_on_sent(&r.sent, &(sentmeta_out){3, 1, 1, 1, 64});
  sentmeta_find(&r.sent, 3); /* present */
  r.io.disp.has_ack       = 1;
  r.io.disp.largest_acked = 3;

  r.rtx_held = 0;
  connrunner_track_loss(&r, 1);
  CHECK(r.rtx_held == 1); /* pn 0 is 3 below largest -> lost */
  CHECK(r.rtx_pn == 0);
  CHECK(sentmeta_find(&r.sent, 0) == SENTMETA_CAP); /* reclaimed */
}

/* A runner with a 1-RTT key installed and the key-update state seeded from it;
 * `confirmed` lifts the handshake-confirmed gate, `secret` makes derivation
 * produce distinct next-generation keys. */
static void mk_ku(connrunner* r, int confirmed) {
  mk_runner(r, 0);
  keyset_install(&r->io.loop.keys, LEVEL_ONERTT, &(initial_keys){0});
  r->io.loop.handshake_confirmed = confirmed;
  connrunner_keyupdate_init(r);
  for (usz i = 0; i < HKDF_PRK; i++) r->ku_secret[i] = (u8)(i + 1);
}

/* RFC 9001 6.2: a peer phase change before the handshake is confirmed must not
 * select the next generation's read key (counterexample the model forbids). */
static void test_ku_no_derive_before_confirm(void) {
  connrunner r;
  mk_ku(&r, 0);
  u8 byte0 = keyphase_set(0x40, 1);              /* opposite phase bit */
  CHECK(connrunner_recv_keygen(&r, byte0) != 1); /* next NOT selected */
  CHECK(r.ku.generation == 0);                   /* send gen unchanged */
  CHECK(r.ku_phase == 0); /* advertised phase unchanged */
}

/* RFC 9001 6.2: confirmed, a phase change selects the next generation's read
 * key; the current generation is still retained and send keys do not advance.
 */
static void test_ku_recv_selects_next_gen(void) {
  connrunner r;
  mk_ku(&r, 1);
  u8 byte0 = keyphase_set(0x40, 1);
  CHECK(connrunner_recv_keygen(&r, byte0) == 1); /* next generation */
  CHECK(r.ku.generation == 0);                   /* send gen unchanged */
}

/* RFC 9001 6.1: initiating derives and rotates keys, retains the old read key,
 * and toggles the phase bit -- send generation becomes 1, phase becomes 1. */
static void test_ku_initiate_derives_then_toggles(void) {
  connrunner r;
  mk_ku(&r, 1);
  r.ku_sent_in_phase = 100;
  CHECK(connrunner_maybe_initiate_ku(&r, &(connrunner_ku_in){100, 10, 1}) == 1);
  CHECK(r.ku.generation == 1);
  CHECK(r.ku.have_old == 1);            /* prior read key retained */
  CHECK(keyphase_get(r.ku_phase) == 1); /* phase == gen%2 */
  CHECK(r.ku_unacked == 1);
}

/* RFC 9001 6.1: an update is blocked before the handshake is confirmed. */
static void test_ku_initiate_blocked_before_confirm(void) {
  connrunner r;
  mk_ku(&r, 0);
  r.ku_sent_in_phase = 100;
  CHECK(connrunner_maybe_initiate_ku(&r, &(connrunner_ku_in){100, 10, 1}) == 0);
  CHECK(r.ku.generation == 0);
}

/* RFC 9001 6.5: a second update is blocked while the first is unacknowledged.
 */
static void test_ku_initiate_blocked_until_acked(void) {
  connrunner r;
  mk_ku(&r, 1);
  r.ku_unacked       = 1; /* a self update still outstanding */
  r.ku_sent_in_phase = 100;
  CHECK(connrunner_maybe_initiate_ku(&r, &(connrunner_ku_in){100, 10, 1}) == 0);
  CHECK(r.ku.generation == 0);
}

/* RFC 9001 6.5: a second update is blocked within 3*PTO of completion. */
static void test_ku_initiate_blocked_within_3pto(void) {
  connrunner r;
  mk_ku(&r, 1);
  r.ku_completed_at  = 10; /* completed at t=10, pto=2 -> floor at 16 */
  r.ku_sent_in_phase = 100;
  CHECK(
      connrunner_maybe_initiate_ku(&r, &(connrunner_ku_in){15, 10, 2}) ==
      0); /* 15 < 16 */
  CHECK(
      connrunner_maybe_initiate_ku(&r, &(connrunner_ku_in){16, 10, 2}) ==
      1); /* 16 >= 16 */
}

/* 1 if two derived traffic secrets are byte-identical. */
static int ku_secret_match(const u8* a, const u8* b) {
  usz i;
  for (i = 0; i < HKDF_PRK; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* RFC 9369 3.3.2: absent a Version Negotiation reconnect, an initiated update
 * derives with the v1 "quic ku" label -- init alone must pin the version. */
static void test_ku_initiate_v1_label_after_init(void) {
  connrunner   r;
  initial_keys expect = {0};
  u8           want[HKDF_PRK];
  mk_ku(&r, 1);
  kuswitch_next_keys_v(VERSION_1, r.ku_secret, &expect, want);
  r.ku_sent_in_phase = 100;
  CHECK(connrunner_maybe_initiate_ku(&r, &(connrunner_ku_in){100, 10, 1}) == 1);
  CHECK(ku_secret_match(r.ku_secret, want));
}

/* RFC 9001 6.5: the old read key is retained for the full 3*PTO window after
 * completion and discarded once it elapses. */
static void test_ku_discard_after_3pto(void) {
  connrunner r;
  mk_ku(&r, 1);
  r.ku_sent_in_phase = 100;
  connrunner_maybe_initiate_ku(&r, &(connrunner_ku_in){0, 10, 2});
  connrunner_ku_completed(&r, 10);                    /* completed at t=10 */
  CHECK(connrunner_maybe_discard_ku(&r, 15, 2) == 0); /* 15 < 16 */
  CHECK(r.ku.have_old == 1);
  CHECK(connrunner_maybe_discard_ku(&r, 16, 2) == 1); /* 16 >= 16 */
  CHECK(r.ku.have_old == 0);
}

/* RFC 9001 6.5: a packet requiring a discarded generation has no key (drop). */
static void test_ku_drop_discarded_gen(void) {
  connrunner r;
  mk_ku(&r, 1);
  r.ku_sent_in_phase = 100;
  connrunner_maybe_initiate_ku(
      &r, &(connrunner_ku_in){0, 10, 2}); /* now at gen 1, phase 1 */
  connrunner_ku_completed(&r, 0);
  connrunner_maybe_discard_ku(&r, 100, 2); /* drop the old gen-0 key */
  u8 old_phase = keyphase_set(0x40, 0);    /* asks for gen 0 */
  CHECK(connrunner_recv_keygen(&r, old_phase) == -1); /* no key */
}

/* RFC 9001 6.2: acknowledging a new-phase packet records the completion time
 * and pins both 3*PTO floors; only a self-initiated update is completed. */
static void test_ku_completion_records_time(void) {
  connrunner r;
  mk_ku(&r, 1);
  r.ku_unacked = 1;
  connrunner_ku_completed(&r, 42);
  CHECK(r.ku_completed_at == 42);
  CHECK(r.ku_unacked == 0);
}

static void test_connrunner_keyupdate(void) {
  test_ku_no_derive_before_confirm();
  test_ku_recv_selects_next_gen();
  test_ku_initiate_derives_then_toggles();
  test_ku_initiate_blocked_before_confirm();
  test_ku_initiate_blocked_until_acked();
  test_ku_initiate_blocked_within_3pto();
  test_ku_initiate_v1_label_after_init();
  test_ku_discard_after_3pto();
  test_ku_drop_discarded_gen();
  test_ku_completion_records_time();
}

static const u8 g_retry_scid[4]  = {0xaa, 0xbb, 0xcc, 0xdd};
static const u8 g_retry_token[3] = {0x01, 0x02, 0x03};

/* Old-shape convenience over the retry_event/vn_lists param objects. */
static int recv_retry_flat(
    connrunner* r,
    int         tag_valid,
    const u8*   scid,
    usz         scid_len,
    const u8*   token,
    usz         token_len) {
  retry_event e = {
      tag_valid, wired_span_of(scid, scid_len),
      wired_span_of(token, token_len)};
  return connrunner_recv_retry(r, &e);
}

static int recv_vn_flat(
    connrunner* r,
    const u32*  offered,
    usz         n_off,
    const u32*  supported,
    usz         n_sup,
    u32*        chosen) {
  vn_lists l = {verlist_of(offered, n_off), verlist_of(supported, n_sup)};
  return connrunner_recv_vn(r, &l, chosen);
}

/* RFC 9000 17.2.5.2: the first valid Retry is accepted, adopts the Retry SCID
 * as the new DCID, and marks the Initial keys stale (re-derivation pending). */
static void test_retry_first_accepted(void) {
  connrunner r;
  mk_runner(&r, 0);
  CHECK(recv_retry_flat(&r, 1, g_retry_scid, 4, g_retry_token, 3) == 1);
  CHECK(r.retry.received == 1);
  CHECK(r.retry.dcid_len == 4 && r.retry.dcid[0] == 0xaa);
  CHECK(r.retry.key_rederive == 1);
}

/* RFC 9000 17.2.5.2: a Retry with an invalid Integrity Tag is discarded. */
static void test_retry_bad_tag_discarded(void) {
  connrunner r;
  mk_runner(&r, 0);
  CHECK(recv_retry_flat(&r, 0, g_retry_scid, 4, g_retry_token, 3) == 0);
  CHECK(r.retry.received == 0);
}

/* RFC 9000 17.2.5.2: a second Retry is discarded (at most one per attempt). */
static void test_retry_second_discarded(void) {
  connrunner r;
  mk_runner(&r, 0);
  CHECK(recv_retry_flat(&r, 1, g_retry_scid, 4, g_retry_token, 3) == 1);
  u8 other[4] = {0x11, 0x22, 0x33, 0x44};
  CHECK(recv_retry_flat(&r, 1, other, 4, g_retry_token, 3) == 0);
  CHECK(r.retry.dcid[0] == 0xaa); /* DCID unchanged by the second Retry */
}

/* RFC 9001 5.2 / RFC 9000 17.2.5.1: the Initial after a Retry re-derives keys
 * for the new DCID before sending and carries the Retry token. */
static void test_retry_rederive_then_token(void) {
  connrunner r;
  mk_runner(&r, 0);
  recv_retry_flat(&r, 1, g_retry_scid, 4, g_retry_token, 3);
  CHECK(connrunner_retry_rederive(&r) == 1);         /* keys re-derived first */
  CHECK(r.io.dcid_len == 4 && r.io.dcid[0] == 0xaa); /* DCID now the SCID */
  CHECK(r.retry.key_rederive == 0);                  /* no stale-key send */
  const u8* tok;
  usz       tlen;
  connrunner_initial_token(&r, &tok, &tlen);
  CHECK(tlen == 3 && tok[0] == 0x01); /* the Retry token rides the Initial */
}

/* RFC 9000 17.2.5.2: a Retry arriving after the handshake progressed is
 * ignored and leaves the DCID unchanged. */
static void test_retry_ignored_after_progress(void) {
  connrunner r;
  mk_runner(&r, 0);
  r.io.loop.handshake_complete = 1; /* the handshake has progressed */
  CHECK(recv_retry_flat(&r, 1, g_retry_scid, 4, g_retry_token, 3) == 0);
  CHECK(r.retry.received == 0);
}

static void test_connrunner_retry(void) {
  test_retry_first_accepted();
  test_retry_bad_tag_discarded();
  test_retry_second_discarded();
  test_retry_rederive_then_token();
  test_retry_ignored_after_progress();
}

#define VER_A 0x00000001u /* the client's sent version */
#define VER_B 0x6b3343cfu /* a common alternative the client also supports */

/* RFC 9000 6.2: VN offering a common version other than the sent one selects
 * it, reconnects, and bumps the VN reconnect count to 1. */
static void test_vn_select_common(void) {
  connrunner r;
  mk_runner(&r, 0);
  r.sent_version = VER_A;
  u32 offered[1] = {VER_B}, supported[2] = {VER_B, VER_A}, chosen = 0;
  CHECK(recv_vn_flat(&r, offered, 1, supported, 2, &chosen) == 1);
  CHECK(chosen == VER_B);
  CHECK(r.vn_retry_count == 1);
}

/* RFC 9000 6.2: a VN whose offered list contains the sent version is a
 * downgrade and is discarded; the sent version is unchanged. */
static void test_vn_downgrade_discarded(void) {
  connrunner r;
  mk_runner(&r, 0);
  r.sent_version = VER_A;
  u32 offered[2] = {VER_A, VER_B}, supported[2] = {VER_B, VER_A}, chosen = 0;
  CHECK(recv_vn_flat(&r, offered, 2, supported, 2, &chosen) == 0);
  CHECK(r.vn_retry_count == 0);
}

/* RFC 9000 6.2: a second VN does not trigger another reconnect. */
static void test_vn_second_no_reconnect(void) {
  connrunner r;
  mk_runner(&r, 0);
  r.sent_version   = VER_A;
  r.vn_retry_count = 1; /* already reconnected once */
  u32 offered[1] = {VER_B}, supported[2] = {VER_B, VER_A}, chosen = 0;
  CHECK(recv_vn_flat(&r, offered, 1, supported, 2, &chosen) == 0);
  CHECK(r.vn_retry_count == 1);
}

/* RFC 9000 6.2: a VN offering no mutually supported version abandons the
 * connection attempt. */
static void test_vn_no_common_abort(void) {
  connrunner r;
  mk_runner(&r, 0);
  r.sent_version = VER_A;
  u32 offered[1] = {0xdead0000u}, supported[2] = {VER_B, VER_A}, chosen = 0;
  CHECK(
      recv_vn_flat(&r, offered, 1, supported, 2, &chosen) ==
      CONNRUNNER_VN_ABORT);
}

/* RFC 9000 6.2: a VN arriving after the handshake progressed is ignored. */
static void test_vn_ignored_after_progress(void) {
  connrunner r;
  mk_runner(&r, 0);
  r.sent_version               = VER_A;
  r.io.loop.handshake_complete = 1;
  u32 offered[1] = {VER_B}, supported[2] = {VER_B, VER_A}, chosen = 0;
  CHECK(recv_vn_flat(&r, offered, 1, supported, 2, &chosen) == 0);
  CHECK(r.vn_retry_count == 0);
}

static void test_connrunner_vn(void) {
  test_vn_select_common();
  test_vn_downgrade_discarded();
  test_vn_second_no_reconnect();
  test_vn_no_common_abort();
  test_vn_ignored_after_progress();
}

void test_connrunner(void) {
  test_packet_level();
  test_process_datagram_owes_ack();
  test_process_datagram_dcid_mismatch_ignored();
  test_unparseable_owes_nothing();
  test_flush_sends_ack();
  test_flush_sends_retransmit();
  test_retransmit_real_bytes();
  test_advance_roundtrip();
  test_advance_closed_idle();
  test_advance_closes_on_violation();
  test_advance_closes_on_aead_limit();
  test_advance_sends_stop_sending_reset();
  test_sentmeta_inflight_tracking();
  test_sentmeta_loss_feeds_rtx();
  test_connrunner_keyupdate();
  test_connrunner_retry();
  test_connrunner_vn();
}
