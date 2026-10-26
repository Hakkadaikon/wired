#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_any_requeued(const srvrun_conn* c);
static int srvrun_pace_or_probe_ok(
    const srvrun_step_ctx* ctx, const srvrun_conn* c);
static usz srvrun_pmtu_probe_payload(u8* buf, usz cap, usz len);
static int srvrun_seal_pmtu_probe(
    srvrun_conn* c, usz size, wired_obuf* out, u64* pn);
static int  srvrun_pmtu_probe_lost(const srvrun_conn* c, u64 now_us);
static void srvrun_pmtu_reap_lost(srvrun_conn* c, u64 now_us);
static usz  srvrun_pmtu_probe_candidate(srvrun_conn* c, u64 now_us);
static int  srvrun_pmtu_send_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, usz size);
static int  srvrun_pmtu_try_probe(const srvrun_step_ctx* ctx, srvrun_conn* c);
static void srvrun_pmtu_chunk_cap(wired_sendsess* s, usz mps);
static void srvrun_pmtu_shrink(srvrun_conn* c);

/* Stream bytes per packet at BASE_PLPMTU (srvrun_mps's formula at the base):
 * a slice longer than this needed a packet above the base. */
#define SRVRUN_PMTU_BASE_SLICE \
  (PMTU_BASE - PMTU_OVERHEAD - SRVRUN_STREAM_HDR_MAX)

/* 1 if any resp[]/wtsend slot has a PTO probe queued (srvrun_has_requeued)
 * -- the round-level trigger for bypassing the pacing gate below. */
static int srvrun_any_requeued(const srvrun_conn* c) {
  return srvrun_any_resp_requeued(c) || srvrun_any_wtsend_requeued(c);
}

/* A probe is owed: a queued retransmit, or a PTO allowance (probe_n) that
 * new data may use. */
static int srvrun_probe_owed(const srvrun_conn* c) {
  return c->l.ackst.probe_n || srvrun_any_requeued(c);
}

/* RFC 9002 7.5: a PTO probe must not be blocked by the congestion
 * controller, and that includes pacing (RFC 9002 7.7) -- not just cwnd. A
 * probe was already exempted from cwnd (srvrun_pump_gate_ok), but the
 * pacing check ahead of it in srvrun_pump_round_gated still gated on
 * c->srtt_ms/next_send_ms, so an RTT spike (a real blackhole off-period's
 * delayed ACK) could push next_send_ms far into the future and silently
 * swallow the one send that would recover the connection -- observed live:
 * a real interop blackhole run stalls mid-transfer and never resumes once
 * the link comes back. */
static int srvrun_pace_or_probe_ok(
    const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  return srvrun_pace_ok(ctx, c) || srvrun_probe_owed(c);
}

/* One pacing-gated round-robin pass: the whole pass (up to SRVRUN_RESP_SLOTS
 * slices, one per slot) counts as a single paced send, so pacing limits how
 * often a PASS may run, not how often each SLOT within it may run -- pacing
 * and round-robin fairness would otherwise fight (a 1ms pacing floor made
 * slot 0's first slice push next_send_ms a full ms into the future before
 * slots 4/8 ever got a turn in the same step, starving them completely). */
int srvrun_pump_round_gated(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (!srvrun_pace_or_probe_ok(ctx, c)) {
    return 0;
  }
  int sent = srvrun_pump_round(ctx, c);
  if (sent) {
    srvrun_pace_next(ctx, c);
  }
  return sent;
}

/* 1 if c already has a DPLPMTUD probe outstanding (srvrun_pmtu_try_probe
 * below has not yet been reconciled by an ACK/LOSS/timer for it) -- RFC 8899
 * 5.1.3 PROBED_SIZE is a single value, so at most one probe is ever
 * outstanding at a time (mirrors connrunner's own pmtu_probe_held, see
 * pmtudrive.c). */
int srvrun_pmtu_probe_outstanding(const srvrun_conn* c) {
  return c->pmtu_probe_pn != SRVRUN_PMTU_NO_PROBE;
}

/* RFC 8899 3.2/5: a PING frame (1 byte, ack-eliciting) followed by PADDING
 * (0x00) filling the rest of len bytes -- carries no application data that
 * would need retransmission if the probe is lost (RFC 8899 3.4). Returns
 * len, or 0 if it does not fit cap. */
static usz srvrun_pmtu_probe_payload(u8* buf, usz cap, usz len) {
  if (len == 0 || len > cap) {
    return 0;
  }
  buf[0] = FRAME_PING;
  bytes_memset(buf + 1, FRAME_PADDING, len - 1);
  return len;
}

/* RFC 8899 4.4/DPLPMTUD: `size` is the target WIRE size -- the UDP datagram
 * byte count DPLPMTUD is asking the path to carry -- not a plaintext frame
 * length. Sealing adds the short header (1 flags + dcid + 4-byte pn) and the
 * AEAD tag on top of the payload, so the plaintext PING+PADDING built below
 * must be shorter than `size` by that overhead or the sealed packet would
 * overshoot the probe's own target. PMTU_OVERHEAD already is this SDK's
 * one worst-case figure for that overhead (max 20-byte dcid + 16-byte tag,
 * see pmtu.h), the same constant pmtu_mps subtracts for the same
 * reason -- reused here instead of a second hand-derived margin. Returns 0
 * if size is at or below the overhead (no room for even a 1-byte PING). */
usz srvrun_pmtu_probe_len(usz size) {
  if (size <= PMTU_OVERHEAD) {
    return 0;
  }
  return size - PMTU_OVERHEAD;
}

/* Seal the PING+PADDING payload above into out as its own 1-RTT packet,
 * under a fresh pn from this connection's own tx_pn sequence (the same
 * counter every other srvrun_seal_* caller advances). Returns 1 with
 * out->len and *pn set, 0 on payload-build or seal failure (pn left
 * unassigned). */
static int srvrun_seal_pmtu_probe(
    srvrun_conn* c, usz size, wired_obuf* out, u64* pn) {
  u8                    pl[PMTU_MAX];
  wired_srvloop_send_in sin;
  usz                   len = srvrun_pmtu_probe_len(size);
  usz                   pln = srvrun_pmtu_probe_payload(pl, sizeof pl, len);
  if (!pln) {
    return 0;
  }
  *pn = c->l.tx_pn++;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      *pn,
      -1,
      wired_span_of(pl, pln),
      0,
      0,
      0,
      0};
  return srvloop_send_onertt_rec(&c->l, &c->s, &sin, out);
}

/* Clear c's outstanding-probe tracking, letting the next opportunity
 * (srvrun_pmtu_probe_candidate) start a fresh probe -- shared by the ACK
 * (srvrun_pmtu_reap_ack) and loss (srvrun_pmtu_reap_lost)
 * resolution paths, both of which must leave at most one probe outstanding
 * (RFC 8899 5.1.3 PROBED_SIZE is a single value). */
void srvrun_pmtu_probe_clear(srvrun_conn* c) {
  c->pmtu_probe_pn      = SRVRUN_PMTU_NO_PROBE;
  c->pmtu_probe_size    = 0;
  c->pmtu_probe_sent_ms = 0;
}

/* The outstanding probe is lost: RFC 9000 14.4 detects a probe's loss like
 * any other packet's, so three later packets acknowledged (RFC 9002 6.1.1
 * kPacketThreshold) declare it, and the RFC 8899 5.1.1 PROBE_TIMER covers a
 * probe nothing after it was acknowledged for. */
static int srvrun_pmtu_probe_lost(const srvrun_conn* c, u64 now_us) {
  if (!srvrun_pmtu_probe_outstanding(c)) {
    return 0;
  }
  return pmtu_probe_timer_due(&c->pmtu, now_us) ||
         loss_by_packet(c->largest_acked, c->pmtu_probe_pn);
}

/* Resolve a lost probe (srvrun_pmtu_probe_lost) into pmtu_on_loss, which
 * re-offers the same size until PROBE_COUNT reaches MAX_PROBES (RFC 8899
 * 5.2). Without this an unanswered probe leaves pmtu_probe_pn outstanding
 * forever and srvrun_pmtu_probe_candidate never starts another. Polled once
 * per send opportunity (srvrun_pmtu_try_probe): this connection has no
 * dedicated timer thread, only per-step polling (see srvrun_pto_deadline_ms's
 * own doc on the same style of poll-driven deadline). */
static void srvrun_pmtu_reap_lost(srvrun_conn* c, u64 now_us) {
  if (!srvrun_pmtu_probe_lost(c, now_us)) {
    return;
  }
  pmtu_on_loss(&c->pmtu, c->pmtu_probe_size);
  srvrun_pmtu_probe_clear(c);
}

/* The next candidate size to probe on c, or 0 if none: a probe already
 * outstanding or a concluded search (pmtu_next_probe's own gate) both
 * read as "nothing to do this opportunity". RFC 8899 5.2: once the
 * PMTU_RAISE_TIMER fires in SEARCH_COMPLETE the search resumes first.
 * now_us converts srvrun's ms clock into pmtu.c's us unit (matching
 * RTT_INITIAL_US and the other RFC 9002 RTT state already on this us
 * clock). */
static usz srvrun_pmtu_probe_candidate(srvrun_conn* c, u64 now_us) {
  srvrun_pmtu_reap_lost(c, now_us);
  if (srvrun_pmtu_probe_outstanding(c)) {
    return 0;
  }
  if (pmtu_raise_timer_due(&c->pmtu, now_us)) {
    pmtu_resume_search(&c->pmtu);
  }
  return pmtu_next_probe(&c->pmtu, now_us);
}

/* Seal and send a `size`-byte probe, then record its pn/size/send-time for
 * the later ACK/LOSS reconciliation step to consume. Returns 1 once a
 * packet actually went out, 0 if this opportunity built nothing (seal
 * failure -- e.g. an unexpected suite/dcid combination this call site did
 * not anticipate). The 0 return matters: srvrun_pmtu_try_probe's caller
 * treats "1 = sent, stop trying other sends this opportunity" as a per-
 * opportunity contract, and pmtu_next_probe (via probe_candidate) keeps
 * re-offering the same candidate size until it is acked/lost/timed out --
 * without this 0, a seal failure at one size would starve every other send
 * on the connection in a tight retry loop, opportunity after opportunity,
 * for as long as that size keeps failing to seal (this is the defensive
 * half of the PMTU_OVERHEAD fix above: with that fix in place this
 * path should not be reachable in practice, but srvrun_pmtu_send_probe must
 * not itself become a hang if it ever is). */
static int srvrun_pmtu_send_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, usz size) {
  u8         buf[PMTU_MAX];
  wired_obuf out = obuf_of(buf, sizeof buf);
  u64        pn;
  if (!srvrun_seal_pmtu_probe(c, size, &out, &pn)) {
    return 0;
  }
  c->pmtu_probe_pn      = pn;
  c->pmtu_probe_size    = size;
  c->pmtu_probe_sent_ms = ctx->now_ms;
  /* RFC 9000 14: a probe still goes out on a halted path (pmtu_halted). */
  srvrun_send_now(
      ctx->cfg, c, wired_span_of(buf, out.len), "PMTU probe sent\n");
  return 1;
}

/* RFC 8899 DPLPMTUD probe send opportunity: try the next candidate size
 * (srvrun_pmtu_probe_candidate) and, if there is one, seal and send it
 * (srvrun_pmtu_send_probe). Returns 1 if a probe was sent this opportunity,
 * 0 if there was nothing to send. */
static int srvrun_pmtu_try_probe(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u64 now_us = ctx->now_ms * 1000;
  usz size   = c->closing ? 0 : srvrun_pmtu_probe_candidate(c, now_us);
  if (!size) {
    return 0;
  }
  return srvrun_pmtu_send_probe(ctx, c, size);
}

/* Transmit while the window has room and slices are ready, across every
 * in-flight response on this connection (RFC 9000 2.2: several requests may
 * be in flight at once) -- round-robin one slice per slot per pass, so a
 * single stream with a full send log never starves its siblings of the
 * connection's one shared cwnd (a strict per-slot drain-then-next order let
 * slot 0 claim the whole window every step; slot 2 fell far enough behind on
 * real send time that its own in-flight slices tripped RFC 9002 6.1.1's
 * packet threshold, not because they were actually lost).
 *
 * RFC 8899 DPLPMTUD probe fairness: each iteration of the loop below is one
 * send opportunity, and a probe attempt is given first refusal on EVERY
 * iteration -- not only once normal sends run dry. An "only after the loop"
 * placement lets a connection with a steady stream of normal sends starve
 * the probe forever: a continuously busy normal-send path never leaves a
 * window where the probe is the only thing with something to send. Trying the
 * probe first, every iteration, gives it the standing to always take its turn
 * the moment it has one (srvrun_pmtu_try_probe itself is a no-op whenever a
 * probe is already outstanding or the search has nothing left to try, so this
 * costs nothing on the common case), while still keeping one send opportunity
 * exclusive to either a probe or a normal pass -- never both (the short-circuit
 * below skips the normal pass on the same opportunity a probe went out). */
int srvrun_pump_opportunity(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (srvrun_pmtu_try_probe(ctx, c)) {
    return 1;
  }
  if (pmtu_halted(&c->pmtu)) {
    return 0; /* RFC 9000 14: the path carries no 1200-byte datagram */
  }
  return srvrun_pump_round_gated(ctx, c);
}

/* RFC 8899 4.3 black hole input: the range [.., hi] the peer acked carried
 * more stream bytes than `hits` BASE_PLPMTU packets could, so an above-base
 * packet at or below hi was delivered. */
void srvrun_pmtu_note_ack(srvrun_conn* c, usz bytes, u64 hits, u64 hi) {
  if (bytes > hits * SRVRUN_PMTU_BASE_SLICE) {
    pmtu_on_big_ack(&c->pmtu, hi);
  }
}

/* 1 if lost packet l was above the base and sent after the newest such
 * packet acked -- evidence the path stopped carrying the PLPMTU. */
int srvrun_pmtu_big_lost(
    const srvrun_conn* c, const wired_sendsess_lost_slice* l) {
  return l->length > SRVRUN_PMTU_BASE_SLICE &&
         pmtu_big_suspect(&c->pmtu, l->pn);
}

static void srvrun_pmtu_chunk_cap(wired_sendsess* s, usz mps) {
  s->q.chunk = (usz)u64_min(s->q.chunk, mps);
}

/* The MPS dropped: every armed send session slices at the new size from
 * now on, retransmissions included (wired_sendsess_take splits). */
static void srvrun_pmtu_shrink(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    srvrun_pmtu_chunk_cap(&c->resp[i].sess, srvrun_mps(c));
  }
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    srvrun_pmtu_chunk_cap(&c->wtsend[i].sess, srvrun_mps(c));
  }
}

/* Feed one loss pass's `big` black hole evidence to the search. On a black
 * hole (RFC 8899 4.3: PLPMTU back to BASE) the slices shrink and any search
 * probe still tracked is dropped, so its loss cannot count against the
 * BASE_PLPMTU probe that BASE sends next (RFC 8899 5.2). */
void srvrun_pmtu_feed_losses(srvrun_conn* c, usz big) {
  usz before = c->pmtu.validated;
  pmtu_on_big_losses(&c->pmtu, big);
  if (c->pmtu.validated == before) {
    return;
  }
  srvrun_pmtu_shrink(c);
  srvrun_pmtu_probe_clear(c);
}

/* RFC 8899 3.5/5.1.2: c's search starts over for its current peer -- the
 * handshake (or the new path's validation) confirmed BASE_PLPMTU, and
 * MAX_PLPMTU is what the local link toward that peer carries (PMTU_MAX
 * when the kernel cannot tell). */
void srvrun_pmtu_start(srvrun_conn* c) {
  usz link = wired_udp_path_mtu(&c->peer);
  pmtu_init(&c->pmtu);
  pmtu_set_max(&c->pmtu, link ? link : PMTU_MAX);
  srvrun_pmtu_probe_clear(c);
}

/* RFC 8899 3 / RFC 9000 14.2: the PLPMTU belongs to one local/remote
 * address pair. The send path moving from `from` to another pair (a peer
 * port change alone keeps it, as for the congestion controller, RFC 9000
 * 9.4) restarts the search at BASE_PLPMTU and re-slices at the base MPS
 * until the new path validates a larger size. */
void srvrun_pmtu_path_reset(
    srvrun_conn* c, const pathsel_key* from, const pathsel_key* to) {
  if (srvrun_path_port_only(from, to)) {
    return;
  }
  srvrun_pmtu_start(c);
  srvrun_pmtu_shrink(c);
}
