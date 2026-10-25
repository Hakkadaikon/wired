#include "app/http3/server/srvloop/send.h"

#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvwire/wire.h"
#include "common/bytes/util/bytes.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/ext/grease/bitset.h"
#include "tls/handshake/core/tls/aead_params.h"
#include "tls/keys/keyupdate/aeadlimit.h"
#include "tls/keys/keyupdate/keyphase.h"
#include "transport/conn/cid/spin/spin.h"
#include "transport/packet/build/hspkt/onertt.h"

/* RFC 9001 5.2: the server Initial is protected with the keys derived from
 * the client's original DCID (odcid), the same value the client opens with --
 * but it is ADDRESSED to in->cli_scid, the client's own SCID (RFC 9000 7.2;
 * possibly zero-length). Writing the odcid into the header instead makes the
 * client discard the reply unread (RFC 9000 5.1) and PTO-retransmit its
 * Initial until it idles out. */
int wired_srvloop_send_initial_ver(
    u32                          version,
    const wired_server*          s,
    const wired_srvloop_send_in* in,
    wired_obuf*                  out) {
  srvwire_seal_in wi = {
      wired_span_of(s->sdrv.odcid, s->sdrv.odcid_len),
      in->cli_scid,
      wired_span_of(s->sdrv.iscid, s->sdrv.iscid_len),
      in->pn,
      in->ack_pn,
      in->payload,
      in->crypto_off,
      in->ect0,
      in->ect1,
      in->ce,
      version};
  return srvwire_seal_initial_ver(version, &wi, out);
}

int wired_srvloop_send_initial(
    const wired_server* s, const wired_srvloop_send_in* in, wired_obuf* out) {
  return wired_srvloop_send_initial_ver(VERSION_1, s, in, out);
}

/* RFC 9001 5 / 5.1: Handshake flight sealed with the own-direction SERVER_HS,
 * addressed to the client's SCID (RFC 9000 7.2). The key-derivation dcid slot
 * is unused at this level (keys come from the schedule). */
int wired_srvloop_send_handshake(
    const wired_server* s, const wired_srvloop_send_in* in, wired_obuf* out) {
  wired_srvloop_dirkeys dk;
  srvwire_seal_in       wi = {
      wired_span_of((const u8*)0, 0),
      in->cli_scid,
      wired_span_of(s->sdrv.iscid, s->sdrv.iscid_len),
      in->pn,
      in->ack_pn,
      in->payload,
      in->crypto_off,
      in->ect0,
      in->ect1,
      in->ce,
      sdrv_wire_version(&s->sdrv)};
  protect_keys k;
  if (!wired_srvloop_seal_keys(s, LEVEL_HANDSHAKE, &dk)) {
    return 0;
  }
  k = (protect_keys){dk.keys, &dk.hp};
  return srvwire_seal_handshake_suite(s->sdrv.cipher_suite, &k, &wi, out);
}

/* RFC 9001 6.2: this endpoint's send-side generation (s->ku_send.cur,
 * advanced by onertt_rotate_send once a peer Key Update is confirmed --
 * RFC 9001 "MUST update its send keys to the corresponding key phase in
 * response"). Falls back to the schedule's fixed generation-0 SERVER_AP only
 * if seeding kuswitch itself failed (should not happen once confirmed; a
 * missing key still fails closed). dk's storage is owned by the caller
 * (wired_srvloop_send_onertt's own stack frame) so the initial_keys*
 * this writes into *out stays valid past this call -- writing dk here
 * instead of taking it as a local would leave *out pointing at a returned
 * stack frame. */
static int send_onertt_keys(
    const wired_server*    s,
    wired_srvloop_dirkeys* dk,
    aes128*                hp,
    protect_keys*          out) {
  if (s->ku_seeded) {
    aes128_init(hp, s->ku_send.cur.hp);
    *out = (protect_keys){&s->ku_send.cur, hp};
    return 1;
  }
  if (!wired_srvloop_seal_keys(s, LEVEL_ONERTT, dk)) {
    return 0;
  }
  *out = (protect_keys){dk->keys, &dk->hp};
  return 1;
}

/* RFC 9001 6.3: the Key Phase bit the wire carries is this endpoint's
 * current send-side generation; 0 (generation 0's phase) before kuswitch is
 * seeded, matching send_onertt_keys's own fallback. */
static int send_onertt_phase(const wired_server* s) {
  return s->ku_seeded ? keyphase_bit(s->ku_send.generation) : 0;
}

/* RFC 9001 6.1/6.2: a self-initiated update needs real generation-0 keys
 * seeded (the handshake confirmed) and the peer caught up to the previous
 * one (its recv generation equal to the send generation). */
static int ku_can_initiate(const wired_server* s) {
  return s->ku_seeded && s->ku_send.generation == s->ku.generation;
}

/* RFC 9001 6.6: once the confidentiality limit for the negotiated AEAD is
 * reached, the current keys MUST NOT seal another packet -- initiate a Key
 * Update (6.1) if allowed, else refuse. Returns 1 if sealing may proceed.
 * ponytail: a limit hit while the previous update is still unconfirmed
 * stalls sends rather than closing the connection; 2^23 packets without one
 * peer packet in the new phase dies of idle timeout first. */
static int ku_limit_gate(wired_server* s) {
  int chacha = aead_is_chacha(s->sdrv.cipher_suite);
  if (!aead_needs_update(s->ku_send_count, chacha)) {
    return 1;
  }
  if (!ku_can_initiate(s)) {
    return 0;
  }
  srvloop_ku_rotate_send(s);
  return 1;
}

/* RFC 9000 10.3: the shortest payload that makes the packet 22 bytes longer
 * than the connection ID the server asks the peer to use (its own iscid),
 * so it cannot be told apart from a Stateless Reset. The short header
 * always carries a 4-byte packet number. */
#define SEND_PAD_MAX 40

static usz send_onertt_min_payload(
    const wired_server* s, const wired_srvloop_send_in* in) {
  usz fixed = 5u + in->cli_scid.n + aead_tag_len(s->sdrv.cipher_suite);
  usz want  = 22u + s->sdrv.iscid_len;
  return want > fixed ? want - fixed : 0;
}

/* pl, or a copy into buf led by enough PADDING frames (0x00) to reach min:
 * leading, so a trailing STREAM frame without a Length still ends the
 * packet. */
static wired_span send_onertt_padded(wired_span pl, usz min, u8* buf) {
  usz pad;
  if (pl.n >= min) {
    return pl;
  }
  pad = min - pl.n;
  bytes_memset(buf, 0, pad);
  bytes_memcpy(buf + pad, pl.p, pl.n);
  return wired_span_of(buf, min);
}

/* RFC 9001 5 / 5.1 / 6: 1-RTT payload sealed with the own-direction
 * SERVER_AP, its Key Phase bit set to this endpoint's current send-side
 * generation (hspkt_onertt_build's byte0 has no way to infer the
 * phase from the keys alone -- the wire bit is the only signal a peer
 * uses to detect an update, RFC 9001 6.3). */
/* RFC 9287 3.1: toward a client that advertised grease_quic_bit, clear the
 * QUIC Bit on about half the 1-RTT packets, the choice keyed by this
 * connection's secret seed so an observer cannot predict it. shortcut: a
 * multiply-mix of seed^pn, not a PRF; swap in a keyed hash if the bit must
 * resist analysis. */
static int send_onertt_clear_bit(const wired_server* s, u64 pn) {
  u64 x = (s->grease_seed ^ pn) * 0x9e3779b97f4a7c15ull;
  return greasebit_may_clear(s->sdrv.peer_grease_quic_bit) && (x >> 63);
}

/* RFC 9000 17.4: the server reflects the spin bit it last saw, unless this
 * connection drew spin disablement (then 0 throughout). */
static int send_onertt_spin(const wired_server* s) {
  return spin_outgoing_ex(1, s->spin_rx, s->spin_off);
}

static int send_onertt_seal(
    const wired_server* s, const wired_srvloop_send_in* in, wired_obuf* out) {
  wired_srvloop_dirkeys dk;
  aes128                hp;
  protect_keys          pk;
  u8                    buf[SEND_PAD_MAX];
  hspkt_onertt_desc     d = {
      in->cli_scid,
      in->pn,
      send_onertt_padded(in->payload, send_onertt_min_payload(s, in), buf),
      send_onertt_phase(s),
      send_onertt_spin(s),
      send_onertt_clear_bit(s, in->pn)};
  if (!send_onertt_keys(s, &dk, &hp, &pk)) {
    return 0;
  }
  return hspkt_onertt_build_suite(s->sdrv.cipher_suite, &pk, &d, out);
}

int wired_srvloop_send_onertt(
    wired_server* s, const wired_srvloop_send_in* in, wired_obuf* out) {
  if (!ku_limit_gate(s)) {
    return 0;
  }
  if (!send_onertt_seal(s, in, out)) {
    return 0;
  }
  s->ku_send_count++; /* RFC 9001 6.6: one more packet under these keys */
  return 1;
}
