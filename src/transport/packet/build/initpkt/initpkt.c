#include "transport/packet/build/initpkt/initpkt.h"

#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/frame/pipeline/txpacket.h"
#include "transport/version/version/v2types.h"

/* RFC 9000 14.1: the protected datagram must reach 1200 bytes. The complete
 * 17.2.2 header (byte0+version+DCID+SCID+empty Token+2-byte Length+4-byte PN)
 * plus the 16-byte AEAD tag forms the overhead; the plaintext payload is padded
 * with PADDING frames (0x00) so header + payload + tag is at least 1200. The
 * 2-byte Length varint holds for any ~1200-byte Initial. */
static usz pad_target(usz dcid_len, usz scid_len) {
  usz overhead = 30u + dcid_len + scid_len;
  return overhead < 1200u ? 1200u - overhead : 0u;
}

static usz initpkt_min_usz(usz a, usz b) { return a < b ? a : b; }

/* Build the CRYPTO frame for the ClientHello, then PADDING-fill to target. */
static int build_payload(
    wired_span crypto, u64 off, usz target, wired_obuf* out) {
  usz                   n, fill = initpkt_min_usz(target, out->cap);
  crypto_stream_emit_in in = {off, crypto.n};
  if (!crypto_stream_emit(crypto, &in, out)) return 0;
  n = out->len;
  for (; n < fill; n++) out->p[n] = 0x00;
  out->len = n;
  return 1;
}

/* RFC 9000 17.2 byte0 for a long-header Initial under `version` (RFC 9000
 * 17.2 for v1, RFC 9369 3.2 for v2). 0 for a version this SDK cannot encode
 * type bits for. */
static u8 initpkt_byte0(u32 version) {
  int wire = version == VERSION_2 ? v2_packet_type(LT_INITIAL)
                                  : v1_packet_type(LT_INITIAL);
  return wire < 0 ? 0 : (u8)(0xC0 | (wire << 4));
}

/* Seal byte0/version/keys/payload into out. Returns 1, or 0 on overflow. */
static int initpkt_seal(
    u8                  byte0,
    u32                 version,
    const initpkt_desc* d,
    const initial_keys* ck,
    wired_span          payload,
    wired_obuf*         out) {
  aes128 hp;
  usz    total;
  aes128_init(&hp, ck->hp);
  protect_keys k = {ck, &hp};
  tx_desc      t = {byte0, d->dcid, d->scid, 1, wired_span_of((const u8*)0, 0),
                    d->pn, payload, version};
  total          = tx_packet(&k, &t, wired_mspan_of(out->p, out->cap));
  if (total == 0) return 0;
  out->len = total;
  return 1;
}

/* RFC 9000 17.2.2 / RFC 9369 3.2-3.3.1: emit a complete Initial long header
 * carrying the SCID and an empty Token under `version`, padded to the
 * 1200-byte datagram floor. */
int initpkt_build_ver(u32 version, const initpkt_desc* d, wired_obuf* out) {
  initial_keys ck, sk;
  u8           payload[1200];
  wired_obuf   po    = obuf_of(payload, sizeof(payload));
  u8           byte0 = initpkt_byte0(version);
  if (byte0 == 0) return 0;
  if (!build_payload(
          d->crypto, d->crypto_off, pad_target(d->dcid.n, d->scid.n), &po))
    return 0;
  initpkt_derive_ver(d->dcid, version, &ck, &sk);
  return initpkt_seal(
      byte0, version, d, &ck, wired_span_of(payload, po.len), out);
}

/* RFC 9000 17.2.2: emit a complete Initial long header carrying the SCID and an
 * empty Token, padded to the 1200-byte datagram floor. */
int initpkt_build(const initpkt_desc* d, wired_obuf* out) {
  return initpkt_build_ver(VERSION_1, d, out);
}
