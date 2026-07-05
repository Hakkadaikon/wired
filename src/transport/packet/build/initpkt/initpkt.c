#include "transport/packet/build/initpkt/initpkt.h"

#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/frame/pipeline/txpacket.h"

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
    quic_span crypto, u64 off, usz target, quic_obuf* out) {
  usz                        n, fill = initpkt_min_usz(target, out->cap);
  quic_crypto_stream_emit_in in = {off, crypto.n};
  if (!quic_crypto_stream_emit(crypto, &in, out)) return 0;
  n = out->len;
  for (; n < fill; n++) out->p[n] = 0x00;
  out->len = n;
  return 1;
}

/* RFC 9000 17.2.2: emit a complete Initial long header carrying the SCID and an
 * empty Token, padded to the 1200-byte datagram floor. */
int quic_initpkt_build(const quic_initpkt_desc* d, quic_obuf* out) {
  quic_initial_keys ck, sk;
  quic_aes128       hp;
  u8                payload[1200];
  quic_obuf         po = quic_obuf_of(payload, sizeof(payload));
  usz               total;
  quic_initpkt_derive(d->dcid, &ck, &sk);
  quic_aes128_init(&hp, ck.hp);
  if (!build_payload(
          d->crypto, d->crypto_off, pad_target(d->dcid.n, d->scid.n), &po))
    return 0;
  quic_protect_keys k = {&ck, &hp};
  quic_tx_desc      t = {
      0xc3,
      d->dcid,
      d->scid,
      1,
      quic_span_of((const u8*)0, 0),
      d->pn,
      quic_span_of(payload, po.len)};
  total = quic_tx_packet(&k, &t, quic_mspan_of(out->p, out->cap));
  if (total == 0) return 0;
  out->len = total;
  return 1;
}
