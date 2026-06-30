#include "transport/version/version/verinfo.h"

#include "common/bytes/util/be.h"

/* RFC 9368 3: value length is Chosen Version (4) + 4 per Available Version. */
static int encode_room(usz cap, usz count, usz n) {
  return count <= QUIC_VI_MAX_AVAILABLE && n <= cap;
}

usz quic_verinfo_encode(u8 *buf, usz cap, const quic_version_information *vi) {
  usz n = 4 + 4 * vi->count;
  if (!encode_room(cap, vi->count, n)) return 0;
  quic_put_be32(buf, vi->chosen);
  for (usz i = 0; i < vi->count; i++)
    quic_put_be32(buf + 4 + 4 * i, vi->available[i]);
  return n;
}

static u32 rd_be32(const u8 *p) {
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* Length must be a multiple of 4, at least 4 (the Chosen Version), and leave
 * no more Available Versions than the array holds. */
static int decode_len_ok(usz n) {
  return n >= 4 && n % 4 == 0 && (n / 4 - 1) <= QUIC_VI_MAX_AVAILABLE;
}

usz quic_verinfo_decode(const u8 *buf, usz n, quic_version_information *vi) {
  usz count;
  if (!decode_len_ok(n)) return 0;
  count      = n / 4 - 1;
  vi->chosen = rd_be32(buf);
  vi->count  = count;
  for (usz i = 0; i < count; i++) vi->available[i] = rd_be32(buf + 4 + 4 * i);
  return n;
}
