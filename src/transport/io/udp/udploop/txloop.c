#include "transport/io/udp/udploop/txloop.h"

#include "common/bytes/util/bytes.h"

usz udploop_pack(const pktsrc* src, wired_obuf* out) {
  usz       off = 0;
  const u8* p   = src->pkts;
  for (usz i = 0; i < src->n_pkts; i++) {
    if (!bytes_put(
            wired_mspan_of(out->p, out->cap), &off,
            wired_span_of(p, src->pkt_lens[i])))
      return 0;
    p += src->pkt_lens[i];
  }
  out->len = off;
  return off;
}

/* The full datagram was sent iff send returned exactly len bytes. */
static int sent_whole(i64 r, usz len) { return r >= 0 && (usz)r == len; }

usz udploop_tx(const udpdst* dst, const pktsrc* src, wired_obuf* out) {
  usz len = udploop_pack(src, out);
  i64 r;
  if (len == 0) return 0; /* RFC 9000 12.2: overflow or nothing to send */
  r = wired_udp_send(dst->fd, dst->peer, wired_span_of(out->p, len));
  return sent_whole(r, len) ? len : 0;
}
