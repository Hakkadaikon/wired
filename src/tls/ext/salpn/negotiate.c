#include "tls/ext/salpn/negotiate.h"

#include "tls/handshake/core/tls/alpn_match.h"

/* RFC 7301 3.1. */

/* Check "h3" at m[*p]; advance *p past the entry (to end on overrun, so the
 * caller's loop stops). Returns 1 only on an in-bounds "h3" match. */
static int entry_is_h3(const u8 *m, usz end, usz *p) {
  usz       nlen = m[*p];
  const u8 *name = m + *p + 1;
  if (*p + 1 + nlen > end) {
    *p = end;
    return 0;
  }
  *p += 1 + nlen;
  return quic_tls_alpn_is_h3(name, nlen);
}

/* ProtocolNameList end offset, or 0 if len is too small or the length field
 * overruns len (so the caller's loop never runs). */
static usz list_end(const u8 *m, usz len) {
  usz end;
  if (len < 2) return 0;
  end = 2 + ((usz)m[0] << 8 | m[1]);
  return end <= len ? end : 0;
}

int quic_salpn_select_h3(const u8 *alpn_ext_data, usz len) {
  usz p = 2, end = list_end(alpn_ext_data, len);
  int hit = 0;
  while (p < end) {
    hit = entry_is_h3(alpn_ext_data, end, &p);
    if (hit) p = end;
  }
  return hit;
}

int quic_salpn_build_response(u8 *out, usz cap, usz *out_len) {
  static const u8 ext[9] = {
      0x00, 0x10,       /* extension_type = ALPN */
      0x00, 0x05,       /* extension_data length */
      0x00, 0x03,       /* ProtocolNameList length */
      0x02, 0x68, 0x33, /* name length + "h3" */
  };
  if (cap < sizeof(ext)) return 0;
  for (usz i = 0; i < sizeof(ext); i++) out[i] = ext[i];
  *out_len = sizeof(ext);
  return 1;
}
