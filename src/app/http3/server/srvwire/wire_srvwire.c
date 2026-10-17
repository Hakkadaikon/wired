#include "app/http3/server/srvwire/wire_impl.h"

/* RFC 9001 5.2 */
int srvwire_seal_initial(const srvwire_seal_in* in, wired_obuf* out) {
  return srvwire_seal_initial_ver(srvwire_ver_or_v1(in->version), in, out);
}

/* RFC 9000 17.2.2: seal pre-built frames (in->tls holds raw frame bytes,
 * e.g. a CONNECTION_CLOSE refusing the connection) into a server Initial
 * without CRYPTO wrapping, plus the usual trailing ACK. */
int srvwire_seal_initial_frames(const srvwire_seal_in* in, wired_obuf* out) {
  u8         frames[1200];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!bytes_put(wired_mspan_of(fb.p, fb.cap), &fb.len, in->tls)) {
    return 0;
  }
  if (!srvwire_append_ack(&fb, in)) {
    return 0;
  }
  return srvwire_initial_tx_ver(srvwire_ver_or_v1(in->version), in, &fb, out);
}

int srvwire_seal_initial_frames_lean(
    const srvwire_seal_in* in, wired_obuf* out) {
  u8         frames[64];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!bytes_put(wired_mspan_of(fb.p, fb.cap), &fb.len, in->tls)) {
    return 0;
  }
  if (!srvwire_append_ack(&fb, in)) {
    return 0;
  }
  return srvwire_initial_tx_lean(in, &fb, out);
}

/* RFC 9001 5.2 */
int srvwire_open_initial(
    const srvwire_open_initial_in* in, wired_mspan pkt, wired_span* tls) {
  initial_keys ck, sk;
  aes128       hp;
  wired_span   frames;
  (void)in->pn;
  initpkt_derive(in->dcid, &ck, &sk);
  aes128_init(&hp, sk.hp);
  protect_keys k = {&sk, &hp};
  rx_desc      d = {pkt, 1, 0};
  if (!rx_packet(&k, &d, &frames)) {
    return 0;
  }
  return srvwire_take_crypto(frames, tls);
}

/* RFC 9001 5. Keys come from the caller, so in->dcid is unused here; the
 * header's DCID is in->hdr_dcid (RFC 9000 7.2). */
int srvwire_seal_handshake(
    const protect_keys* k, const srvwire_seal_in* in, wired_obuf* out) {
  u8         frames[2048];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!srvwire_emit_frames(in, &fb)) {
    return 0;
  }
  hspkt_desc d = {
      in->hdr_dcid, in->scid, in->pn, wired_span_of(frames, fb.len),
      in->version};
  if (!hspkt_build(k, &d, out)) {
    return 0;
  }
  return 1;
}

/* RFC 9001 5 */
int srvwire_open_handshake(
    const protect_keys* k, wired_mspan pkt, wired_span* tls) {
  wired_span frames;
  if (!hspkt_open(k, pkt, 0, &frames)) {
    return 0;
  }
  return srvwire_take_crypto(frames, tls);
}

/* Same as srvwire_seal_handshake, but seals under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int srvwire_seal_handshake_suite(
    u16                    suite,
    const protect_keys*    k,
    const srvwire_seal_in* in,
    wired_obuf*            out) {
  u8         frames[2048];
  wired_obuf fb = obuf_of(frames, sizeof frames);
  if (!srvwire_emit_frames(in, &fb)) {
    return 0;
  }
  hspkt_desc d = {
      in->hdr_dcid, in->scid, in->pn, wired_span_of(frames, fb.len),
      in->version};
  return hspkt_build_suite(suite, k, &d, out);
}

/* Same as srvwire_open_handshake, but opens under the given negotiated
 * TLS 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int srvwire_open_handshake_suite(
    u16 suite, const protect_keys* k, wired_mspan pkt, wired_span* tls) {
  wired_span frames;
  if (!hspkt_open_suite(suite, k, pkt, 0, &frames)) {
    return 0;
  }
  return srvwire_take_crypto(frames, tls);
}
