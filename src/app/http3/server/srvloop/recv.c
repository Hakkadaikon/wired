#include "app/http3/server/srvloop/recv.h"

#include "app/http3/server/srvloop/keys.h"
#include "common/bytes/util/bytes.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/kuswitch/derive.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/build/initpkt/initopen.h"

/* RFC 9001 5.1: open a received Initial under the keys derived from the
 * client's original DCID; the raw frame payload is returned (the dispatcher
 * walks it). in->largest_pn is unused outside the 1-RTT space (the Initial
 * uses a 4-byte PN). */
static int recv_initial(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  return quic_initpkt_open(
      quic_span_of(s->sdrv.odcid, s->sdrv.odcid_len), in->dgram, &out->payload);
}

/* RFC 9001 5.1: open a Handshake packet with the peer-direction CLIENT_HS key.
 * The DCID the client wrote is the server's source id (iscid). */
static int recv_handshake(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  wired_srvloop_dirkeys dk;
  if (!wired_srvloop_open_keys(s, QUIC_LEVEL_HANDSHAKE, &dk)) return 0;
  quic_protect_keys pk = {dk.keys, &dk.hp};
  return quic_hspkt_open(&pk, in->dgram, &out->payload);
}

/* quic_hspkt_onertt_open mutates byte0 and the pn bytes in place (header
 * protection removal, RFC 9001 5.4.1) even on an AEAD failure -- a failed
 * attempt against one key generation must not corrupt the bytes a retry
 * against another generation needs. Cap: pn_off + a 4-byte pn (the longest
 * possible), the same bound quic_hspkt_unprotect itself uses. */
#define RECV_ONERTT_HDR_MAX 24

static usz onertt_hdr_len(u8 dcid_len) { return 1u + (usz)dcid_len + 4u; }

static void onertt_backup(
    quic_mspan pkt, u8 dcid_len, u8 save[RECV_ONERTT_HDR_MAX]) {
  usz n = onertt_hdr_len(dcid_len);
  for (usz i = 0; i < n && i < pkt.n; i++) save[i] = pkt.p[i];
}

static void onertt_restore(
    quic_mspan pkt, u8 dcid_len, const u8 save[RECV_ONERTT_HDR_MAX]) {
  usz n = onertt_hdr_len(dcid_len);
  for (usz i = 0; i < n && i < pkt.n; i++) pkt.p[i] = save[i];
}

/* Try opening with one key candidate; restores the header bytes first so a
 * prior failed attempt against a different generation left no residue
 * (quic_hspkt_onertt_open mutates the datagram's own bytes in place through
 * its pkt view, regardless of how many quic_mspan copies wrap it). */
static int onertt_try(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const quic_initial_keys*     keys,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  quic_aes128 hp;
  quic_aes128_init(&hp, keys->hp);
  {
    quic_protect_keys           pk = {keys, &hp};
    quic_hspkt_onertt_open_desc d  = {
        in->dgram, s->sdrv.iscid_len, in->largest_pn};
    onertt_restore(in->dgram, s->sdrv.iscid_len, save);
    return quic_hspkt_onertt_open(&pk, &d, &out->payload);
  }
}

/* RFC 9001 6.2: this endpoint's own send keys MUST follow a confirmed peer
 * update, in the same generation. Derives independently (server_ap_secret
 * is a different HKDF chain than client_ap_secret) but advances in
 * lockstep with the recv side's rotate. */
static void onertt_rotate_send(wired_server* s) {
  quic_initial_keys send_next;
  u8                send_next_secret[QUIC_HKDF_PRK];
  quic_kuswitch_next_keys(s->ku_send_secret, &send_next, send_next_secret);
  quic_memcpy(send_next.hp, s->ku_send.cur.hp, QUIC_INITIAL_HP);
  quic_kuswitch_rotate(&s->ku_send, &send_next);
  quic_memcpy(s->ku_send_secret, send_next_secret, QUIC_HKDF_PRK);
}

/* RFC 9001 6.3: a next-generation candidate that actually decrypts confirms
 * the peer's update -- rotate so current becomes old (retained) and the
 * derived generation becomes current, and adopt its secret for the update
 * after this one. Only called once a probe has already succeeded. RFC 9001
 * 6.2 requires the send side to follow in the same step (before this
 * packet's ACK goes out, which srvloop's caller does right after opening). */
static void onertt_rotate_to(
    wired_server* s, const quic_initial_keys* next, const u8* next_secret) {
  quic_kuswitch_rotate(&s->ku, next);
  quic_memcpy(s->ku_secret, next_secret, QUIC_HKDF_PRK);
  onertt_rotate_send(s);
}

/* RFC 9001 6.3: current generation first (the common case, every packet
 * until the peer's next update), else retry with old (retained prior
 * generation) so a reordered pre-update packet still decrypts. */
static int onertt_try_known(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  if (onertt_try(s, in, &s->ku.cur, save, out)) return 1;
  return s->ku.have_old && onertt_try(s, in, &s->ku.old, save, out);
}

/* Neither retained generation decrypted it -- the peer's phase bit may name
 * a generation this endpoint has not adopted yet. Derive it once and retry
 * as a probe, rotating only if that probe actually decrypts (RFC 9001:
 * confirm on a successful unprotect, not on the bit alone). */
static int onertt_try_next_gen(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  quic_initial_keys next;
  u8                next_secret[QUIC_HKDF_PRK];
  quic_kuswitch_next_keys(s->ku_secret, &next, next_secret);
  /* RFC 9001 6.1: hp is unchanged across an update. */
  quic_memcpy(next.hp, s->ku.cur.hp, QUIC_INITIAL_HP);
  if (!onertt_try(s, in, &next, save, out)) return 0;
  onertt_rotate_to(s, &next, next_secret);
  return 1;
}

/* RFC 9001 6 depends on generation-0 keys already being seeded (srvfin's
 * confirm, server.c srv_seed_kuswitch) -- before that, s->ku.cur is not real
 * key material, so failing closed here is a structural guarantee, not an
 * incidental AEAD-failure side effect. */
static int recv_onertt(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  u8 save[RECV_ONERTT_HDR_MAX];
  if (!s->ku_seeded) return 0;
  onertt_backup(in->dgram, s->sdrv.iscid_len, save);
  if (onertt_try_known(s, in, save, out)) return 1;
  return onertt_try_next_gen(s, in, save, out);
}

/* RFC 9000 17.2: dispatch the open by level (table keeps CCN low). */
static int recv_at_level(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  static int (*const open_at[])(
      wired_server*, const wired_srvloop_recv_in*, wired_srvloop_recv_out*) = {
      recv_initial,
      recv_handshake,
      recv_onertt,
  };
  return open_at[out->level](s, in, out);
}

int wired_srvloop_recv(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  if (in->dgram.n == 0 ||
      !quic_connrunner_packet_level(in->dgram.p[0], &out->level))
    return 0;
  return recv_at_level(s, in, out);
}
