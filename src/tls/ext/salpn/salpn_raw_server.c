#include "tls/ext/salpn/salpn_raw.h"
#include "tls/ext/salpn/salpn_raw_impl.h"
#include "tls/handshake/core/tls/alpn_match.h"

/* RFC 7301 3.2: selection in this server's preference order. */

/* Entry at w->p is non-empty and inside the list (RFC 7301 3.1:
 * ProtocolName<1..2^8-1>). */
static int salpn_raw_entry_ok(const salpn_raw_walk* w) {
  usz n = w->m[w->p];
  return n != 0 && w->p + 1 + n <= w->end;
}

/* The whole ProtocolNameList parses: a list length that fits, then
 * non-empty entries filling it exactly. */
static int salpn_raw_list_ok(const u8* m, usz len) {
  salpn_raw_walk w  = {m, salpn_raw_list_end(m, len), 2, 0, {0, 0}};
  int            ok = w.end != 0;
  while (ok && w.p < w.end) {
    ok = salpn_raw_entry_ok(&w);
    w.p += 1 + (usz)m[w.p];
  }
  return ok;
}

/* The client's (well-formed) list offers exactly nm. */
static int salpn_raw_offered(const u8* m, usz len, wired_span nm) {
  usz end = salpn_raw_list_end(m, len);
  usz p   = 2;
  int hit = 0;
  while (!hit && p < end) {
    hit = tls_alpn_equal(wired_span_of(m + p + 1, m[p]), nm);
    p += 1 + (usz)m[p];
  }
  return hit;
}

/* The first raw_list entry, in raw_list's own order, the client offered;
 * SALPN_RAW with *tok viewing it, else SALPN_NONE. */
static salpn_choice salpn_raw_first_offered(
    const u8* m, usz len, const char* raw_list, wired_span* tok) {
  const char* p = salpn_raw_str(raw_list);
  while (*p) {
    wired_span nm = wired_span_of((const u8*)p, salpn_raw_tok_len(p));
    if (salpn_raw_offered(m, len, nm)) { /* an empty nm never matches */
      *tok = nm;
      return SALPN_RAW;
    }
    p = salpn_raw_next(p);
  }
  return SALPN_NONE;
}

/* After the raw ids: h3, then hq-interop. */
static salpn_choice salpn_raw_fixed_offered(const u8* m, usz len) {
  if (salpn_select_h3(m, len)) {
    return SALPN_H3;
  }
  return salpn_select_hq(m, len) ? SALPN_HQ : SALPN_NONE;
}

salpn_choice salpn_raw_pick_server(
    const u8* alpn_ext_data, usz len, const char* raw_list, wired_span* tok) {
  salpn_choice c;
  if (!salpn_raw_list_ok(alpn_ext_data, len)) {
    return SALPN_NONE;
  }
  c = salpn_raw_first_offered(alpn_ext_data, len, raw_list, tok);
  return c != SALPN_NONE ? c : salpn_raw_fixed_offered(alpn_ext_data, len);
}
