#include "transport/version/version/verinfo.h"

#include "common/bytes/util/be.h"

/* RFC 9368 3: value length is Chosen Version (4) + 4 per Available Version. */
static int encode_room(usz cap, usz count, usz n) {
  return count <= VI_MAX_AVAILABLE && n <= cap;
}

usz verinfo_encode(u8* buf, usz cap, const version_information* vi) {
  usz n = 4 + 4 * vi->count;
  if (!encode_room(cap, vi->count, n)) {
    return 0;
  }
  be_put_be32(buf, vi->chosen);
  for (usz i = 0; i < vi->count; i++) {
    be_put_be32(buf + 4 + 4 * i, vi->available[i]);
  }
  return n;
}

static u32 rd_be32(const u8* p) {
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* Length must be a multiple of 4, at least 4 (the Chosen Version), and leave
 * no more Available Versions than the array holds. */
static int decode_len_ok(usz n) {
  return n >= 4 && n % 4 == 0 && (n / 4 - 1) <= VI_MAX_AVAILABLE;
}

/* RFC 9368 4: a zero Chosen Version or any zero Available Version is a
 * parsing failure. Every entry, Chosen first, is 4 bytes at buf + 4 * i. */
static int no_zero_version(const u8* buf, usz n) {
  for (usz i = 0; i < n; i += 4) {
    if (rd_be32(buf + i) == 0) {
      return 0;
    }
  }
  return 1;
}

static int verinfo_decode_ok(const u8* buf, usz n) {
  return decode_len_ok(n) && no_zero_version(buf, n);
}

usz verinfo_decode(const u8* buf, usz n, version_information* vi) {
  usz count;
  if (!verinfo_decode_ok(buf, n)) {
    return 0;
  }
  count      = n / 4 - 1;
  vi->chosen = rd_be32(buf);
  vi->count  = count;
  for (usz i = 0; i < count; i++) {
    vi->available[i] = rd_be32(buf + 4 + 4 * i);
  }
  return n;
}

int verinfo_chosen_listed(const version_information* vi) {
  for (usz i = 0; i < vi->count; i++) {
    if (vi->available[i] == vi->chosen) {
      return 1;
    }
  }
  return 0;
}
