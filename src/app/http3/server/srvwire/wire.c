#include "app/http3/server/srvwire/wire.h"

#include "common/bytes/util/bytes.h"
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
#include "transport/version/version/v2types.h"

/* Recover the TLS flight from a packet's CRYPTO frame bytes (RFC 9000 19.6).
 * The CRYPTO frame is emitted first (any ACK frame follows it), so the type
 * byte sits at frames[0] where frame_get_crypto expects it. */
static int srvwire_take_crypto(wired_span frames, wired_span* tls) {
  crypto_frame cf;
  if (!frame_get_crypto(frames.p, frames.n, &cf)) return 0;
  *tls = wired_span_of(cf.data, (usz)cf.length);
  return 1;
}

/* RFC 9000 13.2.1 / 19.3: encode an ACK frame acknowledging the single client
 * packet number ack_pn. Returns bytes written, or 0 on overflow. */
static usz put_ack_one(wired_obuf* out, u64 ack_pn) {
  ack_frame f    = {0};
  f.n_ranges     = 1;
  f.ranges[0].hi = ack_pn;
  f.ranges[0].lo = ack_pn;
  return ack_encode(out->p, out->cap, &f);
}

/* Append an ACK frame for ack_pn after out->len (none when ack_pn < 0). The
 * CRYPTO frame stays at offset 0 so the open path finds it there. Returns 1,
 * or 0 on overflow. */
static int append_ack(wired_obuf* frames, i64 ack_pn) {
  wired_obuf tail;
  usz        a;
  if (ack_pn < 0) return 1;
  tail = obuf_of(frames->p + frames->len, frames->cap - frames->len);
  a    = put_ack_one(&tail, (u64)ack_pn);
  if (a == 0) return 0;
  frames->len += a;
  return 1;
}

/* Build the flight frames into out: the CRYPTO frame(s) for the TLS bytes,
 * then an optional trailing ACK (when in->ack_pn >= 0). Returns 1, or 0 on
 * overflow. */
static int srvwire_emit_frames(
    const quic_srvwire_seal_in* in, wired_obuf* out) {
  crypto_stream_emit_in ein = {in->crypto_off, in->tls.n};
  if (!crypto_stream_emit(in->tls, &ein, out)) return 0;
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
static void pad_initial_frames(wired_obuf* frames, usz floor) {
  usz fill = floor < frames->cap ? floor : frames->cap;
  for (; frames->len < fill; frames->len++) frames->p[frames->len] = 0x00;
}

/* RFC 9000 17.2 byte0 for a long-header Initial under `version`: long form +
 * fixed bit + the version's own Initial type bits (RFC 9000 17.2 for v1,
 * RFC 9369 3.2 for v2 -- lhdr_byte0_pnlen overwrites the low pn_len
 * bits regardless). 0 for a version this SDK cannot encode type bits for. */
static u8 srvwire_initial_byte0(u32 version) {
  int wire = version == QUIC_VERSION_2 ? v2_packet_type(QUIC_LT_INITIAL)
                                       : v1_packet_type(QUIC_LT_INITIAL);
  return wire < 0 ? 0 : (u8)(0xC0 | (wire << 4));
}

/* Pad the built frames to the Initial floor and seal them as one server
 * Initial packet under the server-direction Initial keys for `version`
 * (RFC 9001 5.2 / RFC 9369 3.3.1, derived from in->dcid), with in->hdr_dcid
 * as the header's Destination Connection ID (RFC 9000 7.2: the client's
 * SCID, never the key-derivation DCID -- the peer discards a reply
 * addressed to a CID it does not own). */
static int srvwire_initial_tx_lean_ver(
    u32                         version,
    const quic_srvwire_seal_in* in,
    wired_obuf*                 fb,
    wired_obuf*                 out) {
  initial_keys ck, sk;
  aes128       hp;
  usz          total;
  u8           byte0 = srvwire_initial_byte0(version);
  if (byte0 == 0) return 0;
  initpkt_derive_ver(in->dcid, version, &ck, &sk);
  aes128_init(&hp, sk.hp);
  protect_keys k = {&sk, &hp};
  tx_desc      t = {
      byte0,
      in->hdr_dcid,
      in->scid,
      1,
      wired_span_of((const u8*)0, 0),
      in->pn,
      wired_span_of(fb->p, fb->len),
      version};
  total = tx_packet(&k, &t, wired_mspan_of(out->p, out->cap));
  if (total == 0) return 0;
  out->len = total;
  return 1;
}

static int srvwire_initial_tx_lean(
    const quic_srvwire_seal_in* in, wired_obuf* fb, wired_obuf* out) {
  return srvwire_initial_tx_lean_ver(QUIC_VERSION_1, in, fb, out);
}

/* Pad to the 1200-byte floor, then seal under `version` (the path every
 * CRYPTO-carrying server Initial takes). */
static int srvwire_initial_tx_ver(
    u32                         version,
    const quic_srvwire_seal_in* in,
    wired_obuf*                 fb,
    wired_obuf*                 out) {
  pad_initial_frames(
      fb, init_payload_floor((u8)in->hdr_dcid.n, (u8)in->scid.n));
  return srvwire_initial_tx_lean_ver(version, in, fb, out);
}

/* RFC 9001 5.2 / RFC 9369 3.3.1 */
int quic_srvwire_seal_initial_ver(
    u32 version, const quic_srvwire_seal_in* in, wired_obuf* out) {
  u8         frames[1200]; /* RFC 9000 14.1: room to PADDING to 1200 */
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!srvwire_emit_frames(in, &fb)) return 0;
  return srvwire_initial_tx_ver(version, in, &fb, out);
}

/* RFC 9001 5.2 */
int quic_srvwire_seal_initial(const quic_srvwire_seal_in* in, wired_obuf* out) {
  return quic_srvwire_seal_initial_ver(QUIC_VERSION_1, in, out);
}

/* RFC 9000 17.2.2: seal pre-built frames (in->tls holds raw frame bytes,
 * e.g. a CONNECTION_CLOSE refusing the connection) into a server Initial
 * without CRYPTO wrapping, plus the usual trailing ACK. */
int quic_srvwire_seal_initial_frames(
    const quic_srvwire_seal_in* in, wired_obuf* out) {
  u8         frames[1200];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!bytes_put(wired_mspan_of(fb.p, fb.cap), &fb.len, in->tls)) return 0;
  if (!append_ack(&fb, in->ack_pn)) return 0;
  return srvwire_initial_tx_ver(QUIC_VERSION_1, in, &fb, out);
}

int quic_srvwire_seal_initial_frames_lean(
    const quic_srvwire_seal_in* in, wired_obuf* out) {
  u8         frames[64];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!bytes_put(wired_mspan_of(fb.p, fb.cap), &fb.len, in->tls)) return 0;
  if (!append_ack(&fb, in->ack_pn)) return 0;
  return srvwire_initial_tx_lean(in, &fb, out);
}

/* RFC 9001 5.2 */
int quic_srvwire_open_initial(
    const quic_srvwire_open_initial_in* in, wired_mspan pkt, wired_span* tls) {
  initial_keys ck, sk;
  aes128       hp;
  wired_span   frames;
  (void)in->pn;
  initpkt_derive(in->dcid, &ck, &sk);
  aes128_init(&hp, sk.hp);
  protect_keys k = {&sk, &hp};
  rx_desc      d = {pkt, 1};
  if (!rx_packet(&k, &d, &frames)) return 0;
  return srvwire_take_crypto(frames, tls);
}

/* RFC 9001 5. Keys come from the caller, so in->dcid is unused here; the
 * header's DCID is in->hdr_dcid (RFC 9000 7.2). */
int quic_srvwire_seal_handshake(
    const protect_keys* k, const quic_srvwire_seal_in* in, wired_obuf* out) {
  u8         frames[2048];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!srvwire_emit_frames(in, &fb)) return 0;
  hspkt_desc d = {
      in->hdr_dcid, in->scid, in->pn, wired_span_of(frames, fb.len)};
  if (!hspkt_build(k, &d, out)) return 0;
  return 1;
}

/* RFC 9001 5 */
int quic_srvwire_open_handshake(
    const protect_keys* k, wired_mspan pkt, wired_span* tls) {
  wired_span frames;
  if (!hspkt_open(k, pkt, &frames)) return 0;
  return srvwire_take_crypto(frames, tls);
}

/* Same as quic_srvwire_seal_handshake, but seals under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_srvwire_seal_handshake_suite(
    u16                         suite,
    const protect_keys*         k,
    const quic_srvwire_seal_in* in,
    wired_obuf*                 out) {
  u8         frames[2048];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!srvwire_emit_frames(in, &fb)) return 0;
  hspkt_desc d = {
      in->hdr_dcid, in->scid, in->pn, wired_span_of(frames, fb.len)};
  return hspkt_build_suite(suite, k, &d, out);
}

/* Same as quic_srvwire_open_handshake, but opens under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_srvwire_open_handshake_suite(
    u16 suite, const protect_keys* k, wired_mspan pkt, wired_span* tls) {
  wired_span frames;
  if (!hspkt_open_suite(suite, k, pkt, &frames)) return 0;
  return srvwire_take_crypto(frames, tls);
}
