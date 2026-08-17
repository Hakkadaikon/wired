#include "transport/version/version/version.h"

#include "common/bytes/util/be.h"
#include "common/bytes/varint/varint.h"

int version_is_reserved(u32 version) {
  return (version & 0x0f0f0f0fu) == 0x0a0a0a0au; /* 0x?a?a?a?a pattern */
}

/* The value bytes are: Chosen Version (4) + each Available Version (4). */
static usz vi_value_len(const version_info* vi) {
  return 4 + 4 * vi->n_available;
}

/* Write the Chosen Version and all Available Versions as big-endian u32. */
static void version_put_versions(u8* buf, usz off, const version_info* vi) {
  be_put_be32(buf + off, vi->chosen);
  for (usz i = 0; i < vi->n_available; i++)
    be_put_be32(buf + off + 4 + 4 * i, vi->available[i]);
}

/* A write cursor: buf/cap plus the current offset. */
typedef struct {
  u8*  buf;
  usz  cap;
  usz* off;
} version_wcursor;

/* Write the id and length varints; return 1 ok with *w->off advanced, 0 if no
 * room or too many Available Versions. */
static int put_vi_head(const version_wcursor* w, const version_info* vi) {
  if (vi->n_available > VI_MAX_AVAILABLE) return 0;
  if (!varint_put(
          wired_mspan_of(w->buf, w->cap), w->off, TP_VERSION_INFORMATION))
    return 0;
  return varint_put(wired_mspan_of(w->buf, w->cap), w->off, vi_value_len(vi));
}

usz version_info_encode(u8* buf, usz cap, const version_info* vi) {
  usz             off  = 0;
  usz             vlen = vi_value_len(vi);
  version_wcursor w    = {buf, cap, &off};
  if (!put_vi_head(&w, vi)) return 0;
  if (off + vlen > cap) return 0;
  version_put_versions(buf, off, vi);
  return off + vlen;
}

static u32 version_rd_be32(const u8* p) {
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* A value length is well-formed: a multiple of 4 with the Chosen Version. */
static int vlen_ok(u64 vlen) { return vlen >= 4 && vlen % 4 == 0; }

/* A read cursor: buf/n plus the current offset. */
typedef struct {
  const u8* buf;
  usz       n;
  usz*      off;
} version_rcursor;

/* Read the id varint and require it to be the version_information id. */
static int take_vi_id(const version_rcursor* r) {
  u64 id;
  if (!varint_take(wired_span_of(r->buf, r->n), r->off, &id)) return 0;
  return id == TP_VERSION_INFORMATION;
}

/* Read id and length; require the id to match and the length to be valid. */
static int take_vi_head(const version_rcursor* r, u64* vlen) {
  if (!take_vi_id(r)) return 0;
  if (!varint_take(wired_span_of(r->buf, r->n), r->off, vlen)) return 0;
  return vlen_ok(*vlen);
}

/* Fill chosen + available from the value bytes (count = available count). */
static void read_versions(const u8* value, version_info* vi, usz count) {
  vi->chosen      = version_rd_be32(value);
  vi->n_available = count;
  for (usz i = 0; i < count; i++)
    vi->available[i] = version_rd_be32(value + 4 + 4 * i);
}

/* The value fits in n bytes and its available count fits our array. */
static int vi_fits(usz off, u64 vlen, usz n) {
  return off + vlen <= n && (vlen / 4 - 1) <= VI_MAX_AVAILABLE;
}

usz version_info_decode(const u8* buf, usz n, version_info* vi) {
  usz             off = 0;
  u64             vlen;
  version_rcursor r = {buf, n, &off};
  if (!take_vi_head(&r, &vlen)) return 0;
  if (!vi_fits(off, vlen, n)) return 0;
  read_versions(buf + off, vi, (usz)(vlen / 4 - 1));
  return off + (usz)vlen;
}
