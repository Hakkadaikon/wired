#include "transport/io/socket/net/udp4.h"

#include "common/bytes/util/be.h"
#include "transport/io/socket/net/checksum.h"
#include "transport/io/socket/net/ipv4.h"

#define put_be16 quic_put_be16

/* Sum the IPv4 pseudo-header (src, dst, zero, proto=17, udp_len) into sum. */
static u32 pseudo_sum(u32 sum, u32 src, u32 dst, u16 udp_len) {
  u8 ph[12];
  ph[0] = (u8)(src >> 24);
  ph[1] = (u8)(src >> 16);
  ph[2] = (u8)(src >> 8);
  ph[3] = (u8)src;
  ph[4] = (u8)(dst >> 24);
  ph[5] = (u8)(dst >> 16);
  ph[6] = (u8)(dst >> 8);
  ph[7] = (u8)dst;
  ph[8] = 0;
  ph[9] = QUIC_IP_PROTO_UDP;
  put_be16(ph + 10, udp_len);
  return quic_cksum_accum(sum, ph, 12);
}

/* Write the 8-byte UDP header (ports, length, zero checksum) and payload. */
static void put_udp(
    u8       *out,
    u16       sport,
    u16       dport,
    u16       udp_len,
    const u8 *payload,
    usz       payload_len) {
  put_be16(out, sport);
  put_be16(out + 2, dport);
  put_be16(out + 4, udp_len);
  out[6] = 0;
  out[7] = 0; /* checksum placeholder */
  for (usz i = 0; i < payload_len; i++) out[QUIC_UDP_HDR + i] = payload[i];
}

usz quic_udp4_build(
    u8       *out,
    usz       cap,
    u16       sport,
    u16       dport,
    u32       src,
    u32       dst,
    const u8 *payload,
    usz       payload_len) {
  u16 udp_len = (u16)(QUIC_UDP_HDR + payload_len);
  u32 sum;
  if ((usz)udp_len > cap) return 0;
  put_udp(out, sport, dport, udp_len, payload, payload_len);
  sum = pseudo_sum(0, src, dst, udp_len);
  put_be16(out + 6, quic_cksum_fold(quic_cksum_accum(sum, out, udp_len)));
  return udp_len;
}

int quic_udp4_check(const u8 *dgram, usz len, u32 src, u32 dst) {
  u32 sum = pseudo_sum(0, src, dst, (u16)len);
  return quic_cksum_fold(quic_cksum_accum(sum, dgram, len)) == 0;
}
