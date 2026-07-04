#include "app/http3/server/srvwire/wire.h"

#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/packet/build/hspkt/hspkt_build.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/rxpacket.h"
#include "transport/packet/frame/pipeline/txpacket.h"

/* Recover the TLS flight from a packet's CRYPTO frame bytes (RFC 9000 19.6).
 * The CRYPTO frame is emitted first (any ACK frame follows it), so the type
 * byte sits at frames[0] where quic_frame_get_crypto expects it. */
static int srvwire_take_crypto(quic_span frames, quic_span* tls) {
  quic_crypto_frame cf;
  if (!quic_frame_get_crypto(frames.p, frames.n, &cf)) return 0;
  *tls = quic_span_of(cf.data, (usz)cf.length);
  return 1;
}

/* RFC 9000 13.2.1 / 19.3: encode an ACK frame acknowledging the single client
 * packet number ack_pn. Returns bytes written, or 0 on overflow. */
static usz put_ack_one(quic_obuf* out, u64 ack_pn) {
  quic_ack_frame f = {0};
  f.n_ranges       = 1;
  f.ranges[0].hi   = ack_pn;
  f.ranges[0].lo   = ack_pn;
  return quic_ack_encode(out->p, out->cap, &f);
}

/* Append an ACK frame for ack_pn after out->len (none when ack_pn < 0). The
 * CRYPTO frame stays at offset 0 so the open path finds it there. Returns 1,
 * or 0 on overflow. */
static int append_ack(quic_obuf* frames, i64 ack_pn) {
  quic_obuf tail;
  usz       a;
  if (ack_pn < 0) return 1;
  tail = quic_obuf_of(frames->p + frames->len, frames->cap - frames->len);
  a    = put_ack_one(&tail, (u64)ack_pn);
  if (a == 0) return 0;
  frames->len += a;
  return 1;
}

/* Build the flight frames into out: the CRYPTO frame(s) for the TLS bytes,
 * then an optional trailing ACK (when in->ack_pn >= 0). Returns 1, or 0 on
 * overflow. */
static int srvwire_emit_frames(const quic_srvwire_seal_in* in, quic_obuf* out) {
  quic_crypto_stream_emit_in ein = {in->crypto_off, in->tls.n};
  if (!quic_crypto_stream_emit(in->tls, &ein, out)) return 0;
  return append_ack(out, in->ack_pn);
}

/* RFC 9000 14.1: the server's Initial-carrying datagram must also reach 1200
 * bytes. The complete 17.2.2 header (byte0+version+DCID+SCID+empty Token+2-byte
 * Length+4-byte PN) plus the 16-byte AEAD tag is the overhead; PADDING (0x00)
 * frames after the CRYPTO/ACK pad the plaintext so header+payload+tag >= 1200.
 * curl drops a sub-1200 ServerHello Initial, then PTO-retransmits its own
 * Initial for ~4s (the appconnect stall). */
static usz init_payload_floor(u8 dcid_len, u8 scid_len) {
  usz overhead = 30u + dcid_len + scid_len;
  return overhead < 1200u ? 1200u - overhead : 0u;
}

/* Zero-fill frames up to the 1200-byte Initial floor (bounded by out->cap). */
static void pad_initial_frames(quic_obuf* frames, usz floor) {
  usz fill = floor < frames->cap ? floor : frames->cap;
  for (; frames->len < fill; frames->len++) frames->p[frames->len] = 0x00;
}

/* RFC 9001 5.2 */
int quic_srvwire_seal_initial(const quic_srvwire_seal_in* in, quic_obuf* out) {
  quic_initial_keys ck, sk;
  quic_aes128       hp;
  u8                frames[1200]; /* RFC 9000 14.1: room to PADDING to 1200 */
  quic_obuf         fb = quic_obuf_of(frames, sizeof frames);
  usz               total;
  quic_initpkt_derive(in->dcid, &ck, &sk);
  quic_aes128_init(&hp, sk.hp);
  if (!srvwire_emit_frames(in, &fb)) return 0;
  pad_initial_frames(&fb, init_payload_floor((u8)in->dcid.n, (u8)in->scid.n));
  quic_protect_keys k = {&sk, &hp};
  quic_tx_desc      t = {
      0xc3,
      in->dcid,
      in->scid,
      1,
      quic_span_of((const u8*)0, 0),
      in->pn,
      quic_span_of(frames, fb.len)};
  total = quic_tx_packet(&k, &t, quic_mspan_of(out->p, out->cap));
  if (total == 0) return 0;
  out->len = total;
  return 1;
}

/* RFC 9001 5.2 */
int quic_srvwire_open_initial(
    const quic_srvwire_open_initial_in* in, quic_mspan pkt, quic_span* tls) {
  quic_initial_keys ck, sk;
  quic_aes128       hp;
  quic_span         frames;
  (void)in->pn;
  quic_initpkt_derive(in->dcid, &ck, &sk);
  quic_aes128_init(&hp, sk.hp);
  quic_protect_keys k = {&sk, &hp};
  quic_rx_desc      d = {pkt, 1};
  if (!quic_rx_packet(&k, &d, &frames)) return 0;
  return srvwire_take_crypto(frames, tls);
}

/* RFC 9001 5 */
int quic_srvwire_seal_handshake(
    const quic_protect_keys*    k,
    const quic_srvwire_seal_in* in,
    quic_obuf*                  out) {
  u8        frames[2048];
  quic_obuf fb = quic_obuf_of(frames, sizeof frames);
  if (!srvwire_emit_frames(in, &fb)) return 0;
  quic_hspkt_desc d = {
      in->dcid, in->scid, in->pn, quic_span_of(frames, fb.len)};
  if (!quic_hspkt_build(k, &d, out)) return 0;
  return 1;
}

/* RFC 9001 5 */
int quic_srvwire_open_handshake(
    const quic_protect_keys* k, quic_mspan pkt, quic_span* tls) {
  quic_span frames;
  if (!quic_hspkt_open(k, pkt, &frames)) return 0;
  return srvwire_take_crypto(frames, tls);
}
