#include "transport/packet/build/hspkt/hspkt_build.h"

#include "transport/packet/frame/pipeline/txpacket.h"

/* RFC 9000 17.2.4: byte0 long-header form (0x80), fixed bit (0x40), type bits
 * 5-4 = Handshake (0x2), and a 4-byte packet-number length (low bits 0x03). */
#define HSPKT_BYTE0 0xe3

/* RFC 9000 17.2.4: the long header shared by hspkt_build and
 * hspkt_build_suite. */
static tx_desc hspkt_tx_desc(const hspkt_desc* d) {
  return (tx_desc){HSPKT_BYTE0,         d->dcid, d->scid,    0,
                   wired_span_of(0, 0), d->pn,   d->payload, 0 /* v1 */};
}

/* RFC 9000 17.2.4: emit a complete Handshake long header carrying the SCID and
 * no Token field. */
int hspkt_build(const protect_keys* k, const hspkt_desc* d, wired_obuf* out) {
  tx_desc t     = hspkt_tx_desc(d);
  usz     total = tx_packet(k, &t, wired_mspan_of(out->p, out->cap));
  if (total == 0) return 0;
  out->len = total;
  return 1;
}

/* Same as hspkt_build, but seals under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int hspkt_build_suite(
    u16 suite, const protect_keys* k, const hspkt_desc* d, wired_obuf* out) {
  tx_desc t = hspkt_tx_desc(d);
  usz total = tx_packet_suite(suite, k, &t, wired_mspan_of(out->p, out->cap));
  if (total == 0) return 0;
  out->len = total;
  return 1;
}
