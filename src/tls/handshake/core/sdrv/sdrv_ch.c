#include "tls/handshake/core/sdrv/sdrv_impl.h"

static int sdrv_ch_keyshare_scan(
    const u8* d, usz dlen, u16 want_group, u8 pub[65]);
static int sdrv_ch_one(
    const sdrv_ch_block* blk, usz* q, u16 want_group, u8 pub[65]);

/* Safely read one extension's 4-byte type+length header at *q within blk and
 * advance *q past its declared extension_data. Returns 0 (and leaves *q
 * untouched) if either the header itself or its declared length would run
 * past blk->end. blk->end must already be a validated real bound (see
 * sdrv_ch_exts_span, which clamps the peer's self-reported extensions
 * length to the real ClientHello body before any walk starts); this check
 * is what stops the walk's own loop guard (q + 4 <= end) from being trusted
 * as the sole bounds check -- the loop guard alone permits reading the
 * header before confirming the header's OWN declared length also fits. */
int sdrv_ch_hdr(const sdrv_ch_block* blk, usz* q, unsigned* type, usz* dlen) {
  if (*q + 4 > blk->end) {
    return 0;
  }
  *type = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  *dlen = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  if (*q + 4 + *dlen > blk->end) {
    return 0;
  }
  *q += 4 + *dlen;
  return 1;
}

/* One extension at *q: -1 overrun, 1 want_group's key_share taken, 0 skip;
 * *q advances. RFC 8446 4.2.8: the ClientHello key_share lists several
 * KeyShareEntry, so scan the list for want_group rather than assuming it is
 * the first entry. */
static int sdrv_ch_keyshare_scan(
    const u8* d, usz dlen, u16 want_group, u8 pub[65]) {
  usz pub_len;
  return tls_ext_key_share_scan(d, dlen, want_group, pub, &pub_len, 65);
}

static int sdrv_ch_one(
    const sdrv_ch_block* blk, usz* q, u16 want_group, u8 pub[65]) {
  unsigned type;
  usz      dlen, start = *q;
  if (!sdrv_ch_hdr(blk, q, &type, &dlen)) {
    return -1;
  }
  return (type == EXT_KEY_SHARE)
             ? sdrv_ch_keyshare_scan(blk->b + start + 4, dlen, want_group, pub)
             : 0;
}

int sdrv_ch_walk(const u8* b, usz q, usz end, u16 want_group, u8 pub[65]) {
  sdrv_ch_block blk = {b, end};
  int           r   = 0;
  while (r == 0 && q + 4 <= end) {
    r = sdrv_ch_one(&blk, &q, want_group, pub);
  }
  return r == 1;
}

/* The length field of a w-byte-prefixed vector at p is in range. */
int sdrv_prefix_fits(usz p, usz w, usz n) { return p != 0 && p + w <= n; }

/* Read the w-byte big-endian length at p (w is 1 or 2). */
usz sdrv_prefix_len(const u8* b, usz p, usz w) {
  return w == 1 ? b[p] : ((usz)b[p] << 8 | b[p + 1]);
}

/* Skip a w-byte-length-prefixed vector at p; return the offset past it
 * (0 = overrun). */
usz sdrv_skip_vec(wired_span b, usz p, usz w) {
  if (!sdrv_prefix_fits(p, w, b.n)) {
    return 0;
  }
  p += w + sdrv_prefix_len(b.p, p, w);
  return p <= b.n ? p : 0;
}

/* RFC 8446 4.1.2: offset of the extensions-length field, or 0 on overrun. */
usz sdrv_ch_prefix(const u8* b, usz n) {
  wired_span span = wired_span_of(b, n);
  usz p = sdrv_skip_vec(span, 34, 1); /* session_id after version+random */
  p     = sdrv_skip_vec(span, p, 2);  /* cipher_suites */
  p     = sdrv_skip_vec(span, p, 1);  /* compression_methods */
  return sdrv_prefix_fits(p, 2, n) ? p : 0;
}
