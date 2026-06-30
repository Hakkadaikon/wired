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
static int srvwire_take_crypto(
    const u8 *frames, usz n, const u8 **tls, usz *tls_len) {
  quic_crypto_frame cf;
  if (!quic_frame_get_crypto(frames, n, &cf)) return 0;
  *tls     = cf.data;
  *tls_len = (usz)cf.length;
  return 1;
}

/* RFC 9000 13.2.1 / 19.3: encode an ACK frame acknowledging the single client
 * packet number ack_pn. Returns bytes written, or 0 on overflow. */
static usz put_ack_one(u8 *frames, usz cap, u64 ack_pn) {
  quic_ack_frame f = {0};
  f.n_ranges       = 1;
  f.ranges[0].hi   = ack_pn;
  f.ranges[0].lo   = ack_pn;
  return quic_ack_encode(frames, cap, &f);
}

/* Append an ACK frame for ack_pn after the CRYPTO frames (none when ack_pn <
 * 0). The CRYPTO frame stays at offset 0 so the open path finds it there.
 * Updates *fl with the appended length. Returns 1, or 0 on overflow. */
static int append_ack(i64 ack_pn, u8 *frames, usz cap, usz *fl) {
  usz a;
  if (ack_pn < 0) return 1;
  a = put_ack_one(frames + *fl, cap - *fl, (u64)ack_pn);
  if (a == 0) return 0;
  *fl += a;
  return 1;
}

/* Build the flight frames: the CRYPTO frame(s) for the TLS bytes, then an
 * optional trailing ACK (when ack_pn >= 0). Returns 1, or 0 on overflow. */
static int srvwire_emit_frames(
    i64 ack_pn, const u8 *tls, usz tls_len, u8 *frames, usz cap, usz *fl) {
  if (!quic_crypto_stream_emit(tls, tls_len, 0, tls_len, frames, cap, fl))
    return 0;
  return append_ack(ack_pn, frames, cap, fl);
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

/* Zero-fill frames up to the 1200-byte Initial floor (bounded by cap). */
static void pad_initial_frames(u8 *frames, usz cap, usz *fl, usz floor) {
  usz fill = floor < cap ? floor : cap;
  for (; *fl < fill; (*fl)++) frames[*fl] = 0x00;
}

/* RFC 9001 5.2 */
int quic_srvwire_seal_initial(
    const u8 *dcid,
    u8        dcid_len,
    const u8 *scid,
    u8        scid_len,
    u64       pn,
    i64       ack_pn,
    const u8 *tls,
    usz       tls_len,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  quic_initial_keys ck, sk;
  quic_aes128       hp;
  u8                frames[1200]; /* RFC 9000 14.1: room to PADDING to 1200 */
  usz               fl, total;
  quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
  quic_aes128_init(&hp, sk.hp);
  if (!srvwire_emit_frames(ack_pn, tls, tls_len, frames, sizeof frames, &fl))
    return 0;
  pad_initial_frames(
      frames, sizeof frames, &fl, init_payload_floor(dcid_len, scid_len));
  total = quic_tx_packet(
      &sk, &hp, 0xc3, dcid, dcid_len, scid, scid_len, 1, (const u8 *)0, 0, pn,
      frames, fl, out, cap);
  if (total == 0) return 0;
  *out_len = total;
  return 1;
}

/* RFC 9001 5.2 */
int quic_srvwire_open_initial(
    const u8  *dcid,
    u8         dcid_len,
    u8        *pkt,
    usz        len,
    u64        pn,
    const u8 **tls,
    usz       *tls_len) {
  quic_initial_keys ck, sk;
  quic_aes128       hp;
  const u8         *frames;
  usz               fl;
  (void)pn;
  quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
  quic_aes128_init(&hp, sk.hp);
  if (!quic_rx_packet(&sk, &hp, pkt, len, 1, &frames, &fl)) return 0;
  return srvwire_take_crypto(frames, fl, tls, tls_len);
}

/* RFC 9001 5 */
int quic_srvwire_seal_handshake(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    const u8                *dcid,
    u8                       dcid_len,
    const u8                *scid,
    u8                       scid_len,
    u64                      pn,
    i64                      ack_pn,
    const u8                *tls,
    usz                      tls_len,
    u8                      *out,
    usz                      cap,
    usz                     *out_len) {
  u8  frames[2048];
  usz fl;
  if (!srvwire_emit_frames(ack_pn, tls, tls_len, frames, sizeof frames, &fl))
    return 0;
  return quic_hspkt_build(
      keys, hp, dcid, dcid_len, scid, scid_len, pn, frames, fl, out, cap,
      out_len);
}

/* RFC 9001 5 */
int quic_srvwire_open_handshake(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    u8                       dcid_len,
    const u8               **tls,
    usz                     *tls_len) {
  const u8 *frames;
  usz       fl;
  if (!quic_hspkt_open(keys, hp, pkt, len, dcid_len, &frames, &fl)) return 0;
  return srvwire_take_crypto(frames, fl, tls, tls_len);
}
