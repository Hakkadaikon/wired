#include "transport/io/socket/net/udp4.h"

#include "common/bytes/util/be.h"
#include "transport/io/socket/net/checksum.h"
#include "transport/io/socket/net/ipv4.h"

#define put_be16 quic_put_be16

/* Sum the IPv4 pseudo-header (src, dst, zero, proto=17, udp_len) into sum. */
static u32 pseudo_sum(u32 sum, quic_ipv4addrs addrs, u16 udp_len) {
  u8 ph[12];
  ph[0] = (u8)(addrs.src >> 24);
  ph[1] = (u8)(addrs.src >> 16);
  ph[2] = (u8)(addrs.src >> 8);
  ph[3] = (u8)addrs.src;
  ph[4] = (u8)(addrs.dst >> 24);
  ph[5] = (u8)(addrs.dst >> 16);
  ph[6] = (u8)(addrs.dst >> 8);
  ph[7] = (u8)addrs.dst;
  ph[8] = 0;
  ph[9] = QUIC_IP_PROTO_UDP;
  put_be16(ph + 10, udp_len);
  return quic_cksum_accum(sum, ph, 12);
}

/* Write the 8-byte UDP header (ports, length, zero checksum) and payload. */
static void put_udp(u8* out, quic_udpports ports, quic_span payload) {
  u16 udp_len = (u16)(QUIC_UDP_HDR + payload.n);
  put_be16(out, ports.sport);
  put_be16(out + 2, ports.dport);
  put_be16(out + 4, udp_len);
  out[6] = 0;
  out[7] = 0; /* checksum placeholder */
  for (usz i = 0; i < payload.n; i++) out[QUIC_UDP_HDR + i] = payload.p[i];
}

usz quic_udp4_build(
    quic_obuf* out, const quic_udp4meta* meta, quic_span payload) {
  u16 udp_len = (u16)(QUIC_UDP_HDR + payload.n);
  u32 sum;
  if ((usz)udp_len > out->cap) return 0;
  put_udp(out->p, meta->ports, payload);
  sum = pseudo_sum(0, meta->addrs, udp_len);
  put_be16(out->p + 6, quic_cksum_fold(quic_cksum_accum(sum, out->p, udp_len)));
  out->len = udp_len;
  return udp_len;
}

int quic_udp4_check(quic_span dgram, quic_ipv4addrs addrs) {
  u32 sum = pseudo_sum(0, addrs, (u16)dgram.n);
  return quic_cksum_fold(quic_cksum_accum(sum, dgram.p, dgram.n)) == 0;
}
