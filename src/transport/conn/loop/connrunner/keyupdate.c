#include "transport/conn/loop/connrunner/keyupdate.h"

#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/keyupdate/keyphase.h"
#include "tls/keys/kudrive/discard_timing.h"
#include "tls/keys/kudrive/recv_phase.h"
#include "tls/keys/kudrive/trigger.h"
#include "tls/keys/kuswitch/derive.h"
#include "tls/keys/kuswitch/phasebit.h"

/* The current generation's installed 1-RTT keys, or a zeroed set if none. */
static void cur_keys(const quic_connrunner *r, quic_initial_keys *out) {
  const quic_initial_keys *k;
  quic_initial_keys        z = {0};
  *out =
      quic_keyset_for_level(&r->io.loop.keys, QUIC_LEVEL_ONERTT, &k) ? *k : z;
}

void quic_connrunner_keyupdate_init(quic_connrunner *r) {
  quic_initial_keys gen0;
  usz               i;
  cur_keys(r, &gen0);
  quic_kuswitch_init(&r->ku, &gen0);
  for (i = 0; i < QUIC_HKDF_PRK; i++) r->ku_secret[i] = 0;
  r->ku_phase         = 0; /* RFC 9001 6.2: generation 0 => phase bit 0 */
  r->ku_completed_at  = (u64)-1;
  r->ku_sent_in_phase = 0;
  r->ku_unacked       = 0;
}

/* RFC 9001 6.2: a peer phase change is only honoured once the handshake is
 * confirmed (mirrors the initiate gate); the compound lives here, not inline.
 */
static int recv_next_allowed(
    const quic_connrunner *r, int recv_bit, int cur_bit) {
  return r->io.loop.handshake_confirmed &&
         quic_kudrive_key_generation(recv_bit, cur_bit, r->ku_unacked);
}

/* RFC 9001 6.2/6.3: a confirmed peer phase change selects the next generation's
 * read key (derived on the follow). A differing bit while the current
 * generation already retains an old key, or before confirmation, names that
 * existing generation rather than a new one. */
static int select_next(const quic_connrunner *r, int recv_bit, int cur_bit) {
  return r->ku.generation == 0 && recv_next_allowed(r, recv_bit, cur_bit);
}

int quic_connrunner_recv_keygen(quic_connrunner *r, u8 byte0) {
  int recv_bit = quic_keyphase_get(byte0);
  int cur_bit  = (int)quic_kuswitch_phase_bit(r->ku.generation);
  const quic_initial_keys *keys;
  /* A peer update to a brand-new generation (no old retained yet) is the only
   * case that derives a next read key; everything else must already hold a
   * key for the bit, or the packet is dropped (RFC 9001 6.5). */
  if (select_next(r, recv_bit, cur_bit)) return 1;
  if (!quic_kuswitch_key_for_phase(&r->ku, recv_bit, &keys)) return -1;
  return 0; /* current or retained old generation */
}

/* RFC 9001 6.5: with no prior completed update the re-initiation floor does not
 * apply; otherwise 3*PTO must have elapsed since the last completion. */
static int reinit_floor_ok(const quic_connrunner *r, u64 now, u64 pto) {
  if (r->ku_completed_at == (u64)-1) return 1;
  return quic_kudrive_can_initiate_again(now, r->ku_completed_at, pto);
}

/* RFC 9001 6.1/6.5: both initiate gates -- threshold reached, confirmed, no
 * unacked self update, and the 3*PTO re-initiation floor cleared. */
static int may_initiate(const quic_connrunner *r, const quic_connrunner_ku_in *in) {
  return quic_kudrive_should_initiate(
             r->ku_sent_in_phase, in->threshold,
             r->io.loop.handshake_confirmed) &&
         !r->ku_unacked && reinit_floor_ok(r, in->now, in->pto);
}

/* RFC 9001 6.1: derive the next generation's keys, rotate them in, install them
 * as the 1-RTT keyset, then toggle the advertised phase bit -- in that order.
 */
static void do_initiate(quic_connrunner *r) {
  quic_initial_keys next = {0};
  u8                next_secret[QUIC_HKDF_PRK];
  quic_kuswitch_next_keys(r->ku_secret, &next, next_secret);
  quic_kuswitch_rotate(&r->ku, &next); /* derive/rotate ... */
  for (usz i = 0; i < QUIC_HKDF_PRK; i++) r->ku_secret[i] = next_secret[i];
  quic_keyset_install(&r->io.loop.keys, QUIC_LEVEL_ONERTT, &next);
  quic_kuswitch_apply_phase(
      &r->ku_phase, r->ku.generation); /* ... before toggle */
  r->ku_unacked       = 1;
  r->ku_completed_at  = (u64)-1; /* RFC 9001 6.2: reset clocks */
  r->ku_sent_in_phase = 0;
}

int quic_connrunner_maybe_initiate_ku(quic_connrunner *r, const quic_connrunner_ku_in *in) {
  if (!may_initiate(r, in)) return 0;
  do_initiate(r);
  return 1;
}

/* RFC 9001 6.5: only discard once an update has completed and 3*PTO elapsed. */
static int may_discard(const quic_connrunner *r, u64 now, u64 pto) {
  return r->ku.have_old && r->ku_completed_at != (u64)-1 &&
         quic_kudrive_can_discard_old(now, r->ku_completed_at, pto);
}

int quic_connrunner_maybe_discard_ku(quic_connrunner *r, u64 now, u64 pto) {
  if (!may_discard(r, now, pto)) return 0;
  quic_kuswitch_discard_old(&r->ku);
  return 1;
}

void quic_connrunner_ku_completed(quic_connrunner *r, u64 now) {
  if (!r->ku_unacked) return; /* nothing self-initiated to complete */
  r->ku_completed_at = now;   /* RFC 9001 6.2: pins both 3*PTO floors */
  r->ku_unacked      = 0;
}
