#include "transport/packet/header/packet/coalesce.h"

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"

void quic_coalesce_begin(quic_coalesce_iter* it, const u8* dgram, usz total) {
  it->dgram = dgram;
  it->total = total;
  it->off   = 0;
}

/* Skip one length-prefixed connection ID at *p (n total). Returns 1 ok. */
static int skip_cid(const u8* buf, usz n, usz* p) {
  if (*p >= n) return 0;
  *p += 1 + (usz)buf[*p];
  return *p <= n;
}

/* Long-header types that carry a token before the Length field (Initial). */
static int has_token(u8 byte0) {
  return ((byte0 >> 4) & 0x3) == 0x0; /* WIRED_LP_INITIAL */
}

/* Skip the Initial token (a varint length plus that many bytes). */
static int skip_token(const u8* buf, usz n, usz* p) {
  u64 tlen;
  if (!quic_varint_take(quic_span_of(buf, n), p, &tlen)) return 0;
  *p += (usz)tlen;
  return *p <= n;
}

/* Advance *p over the version and both connection IDs of a long header. */
static int skip_long_prefix(const u8* buf, usz n, usz* p) {
  *p += 5; /* byte0 + 4-byte version */
  if (*p > n || !skip_cid(buf, n, p)) return 0;
  return skip_cid(buf, n, p);
}

/* Advance *p past the prefix and, for an Initial packet, the token. The
 * packet starts at buf.p[*p] == the header's byte0 on entry. */
static int skip_to_length(quic_span buf, usz* p) {
  u8 byte0 = buf.p[*p];
  if (!skip_long_prefix(buf.p, buf.n, p)) return 0;
  if (!has_token(byte0)) return 1;
  return skip_token(buf.p, buf.n, p);
}

/* Read the Length varint at *p and bound the packet [off, *p+Length);
 * returns its total length from off, or 0 if it runs past the datagram. */
static usz take_length_bound(quic_span buf, usz off, usz* p) {
  u64 length;
  if (!quic_varint_take(quic_span_of(buf.p, buf.n), p, &length)) return 0;
  if (*p + (usz)length > buf.n) return 0;
  return *p - off + (usz)length;
}

/* Total bytes of the long-header packet at off, or 0 if malformed. */
static usz long_packet_len(const u8* buf, usz n, usz off) {
  usz p = off;
  if (!skip_to_length(quic_span_of(buf, n), &p)) return 0;
  return take_length_bound(quic_span_of(buf, n), off, &p);
}

/* Emit a packet [off, off+len) and advance the cursor by len. */
static int coalesce_emit(quic_coalesce_iter* it, quic_coalesced* out, usz len) {
  if (len == 0) return 0;
  out->data = it->dgram + it->off;
  out->len  = len;
  it->off += len;
  return 1;
}

int quic_coalesce_next(quic_coalesce_iter* it, quic_coalesced* out) {
  usz rest = it->total - it->off;
  if (it->off >= it->total) return 0;
  if ((it->dgram[it->off] & 0x80) == 0)
    return coalesce_emit(it, out, rest); /* short */
  return coalesce_emit(it, out, long_packet_len(it->dgram, it->total, it->off));
}
