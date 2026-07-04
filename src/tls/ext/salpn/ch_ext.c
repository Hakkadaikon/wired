#include "tls/ext/salpn/ch_ext.h"

/* RFC 8446 4.1.2. */

static u16 rd16(const u8* p) { return (u16)((u16)p[0] << 8 | p[1]); }

/* Skip a vector with a 1-byte length prefix at *p (end bound). Returns 1. */
static int salpn_skip_v8(const u8* m, usz end, usz* p) {
  usz n;
  if (*p + 1 > end) return 0;
  n = m[*p];
  *p += 1 + n;
  return *p <= end;
}

/* Skip a vector with a 2-byte length prefix at *p (end bound). Returns 1. */
static int salpn_skip_v16(const u8* m, usz end, usz* p) {
  usz n;
  if (*p + 2 > end) return 0;
  n = rd16(m + *p);
  *p += 2 + n;
  return *p <= end;
}

/* Advance *p from the body start past the fixed/variable prefix to the
 * extensions length field. Returns 1 if it lands within end. */
static int to_exts(const u8* m, usz end, usz* p) {
  *p += 2 + 32;                             /* legacy_version + random */
  if (!salpn_skip_v8(m, end, p)) return 0;  /* session_id */
  if (!salpn_skip_v16(m, end, p)) return 0; /* cipher_suites */
  return salpn_skip_v8(m, end, p);          /* legacy_compression_methods */
}

/* Scan bounds: buffer, cursor, block end, and the extension_type sought. */
typedef struct {
  const u8* m;
  usz       q;
  usz       end;
  u16       ext_type;
} salpn_scan_in;

/* One extension at in->q: -1 overrun, 0 mismatch (advance), 1 match. */
static int one_ext(salpn_scan_in* in, quic_span* ext) {
  usz dlen = rd16(in->m + in->q + 2);
  if (in->q + 4 + dlen > in->end) return -1;
  if (rd16(in->m + in->q) == in->ext_type) {
    *ext = quic_span_of(in->m + in->q + 4, dlen);
    return 1;
  }
  in->q += 4 + dlen;
  return 0;
}

/* Scan the extensions block [q,end) for ext_type. */
static int scan(salpn_scan_in* in, quic_span* ext) {
  while (in->q + 4 <= in->end) {
    int r = one_ext(in, ext);
    if (r != 0) return r > 0;
  }
  return 0;
}

/* [q,end) bounds of the extensions block within a message of length n. */
typedef struct {
  usz q;
  usz end;
} salpn_bounds;

/* Read the 2-byte extensions block length at p and set bounds. */
static int block_end(quic_span m, usz p, salpn_bounds* b) {
  if (p + 2 > m.n) return 0;
  b->end = p + 2 + rd16(m.p + p);
  b->q   = p + 2;
  return b->end <= m.n;
}

/* Locate the extensions block end and capture its start. */
static int exts_bounds(quic_span m, salpn_bounds* b) {
  usz p = 4; /* msg_type(1) + length(3) */
  if (!to_exts(m.p, m.n, &p)) return 0;
  return block_end(m, p, b);
}

int quic_salpn_find_extension(quic_span ch_msg, u16 ext_type, quic_span* ext) {
  salpn_bounds  b;
  salpn_scan_in in;
  if (!exts_bounds(ch_msg, &b)) return 0;
  in = (salpn_scan_in){ch_msg.p, b.q, b.end, ext_type};
  return scan(&in, ext);
}
