#include "transport/io/socket/net/udp4.h"

#include "common/bytes/util/be.h"
#include "transport/io/socket/net/checksum.h"
#include "transport/io/socket/net/ipv4.h"

#define put_be16 be_put_be16

/* Sum the IPv4 pseudo-header (src, dst, zero, proto=17, udp_len) into sum. */
static u32 pseudo_sum(u32 sum, ipv4addrs addrs, u16 udp_len) {
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
  ph[9] = IP_PROTO_UDP;
  put_be16(ph + 10, udp_len);
  return cksum_accum(sum, ph, 12);
}

/* Write the 8-byte UDP header (ports, length, zero checksum) and payload. */
static void put_udp(u8* out, udpports ports, wired_span payload) {
  u16 udp_len = (u16)(UDP_HDR + payload.n);
  put_be16(out, ports.sport);
  put_be16(out + 2, ports.dport);
  put_be16(out + 4, udp_len);
  out[6] = 0;
  out[7] = 0; /* checksum placeholder */
  for (usz i = 0; i < payload.n; i++) out[UDP_HDR + i] = payload.p[i];
}

/* RFC 768 "Fields": a checksum that computes to zero is transmitted as all
 * ones, because an all-zero field is reserved to mean "no checksum sent". */
static u16 udp_cksum_field(u16 folded) {
  return folded == 0 ? 0xffffu : folded;
}

usz udp4_build(wired_obuf* out, const udp4meta* meta, wired_span payload) {
  u16 udp_len = (u16)(UDP_HDR + payload.n);
  u32 sum;
  u16 folded;
  if ((usz)udp_len > out->cap) return 0;
  put_udp(out->p, meta->ports, payload);
  sum    = pseudo_sum(0, meta->addrs, udp_len);
  folded = cksum_fold(cksum_accum(sum, out->p, udp_len));
  put_be16(out->p + 6, udp_cksum_field(folded));
  out->len = udp_len;
  return udp_len;
}

/* RFC 768 "Fields": an all-zero checksum field means the sender generated
 * no checksum, for debugging or a higher-level protocol that doesn't care. */
static int udp_cksum_absent(const u8* dgram) {
  return dgram[6] == 0 && dgram[7] == 0;
}

/* An all-zero checksum field is accepted unverified (see udp_cksum_absent);
 * otherwise the pseudo-header sum over the datagram must fold to zero. */
int udp4_check(wired_span dgram, ipv4addrs addrs) {
  u32 sum;
  if (dgram.n < UDP_HDR) return 0;
  if (udp_cksum_absent(dgram.p)) return 1;
  sum = pseudo_sum(0, addrs, (u16)dgram.n);
  return cksum_fold(cksum_accum(sum, dgram.p, dgram.n)) == 0;
}
