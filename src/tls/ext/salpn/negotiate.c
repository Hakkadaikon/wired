#include "tls/ext/salpn/negotiate.h"

#include "tls/handshake/core/tls/alpn_match.h"

/* RFC 7301 3.1. */

/* One ProtocolNameList entry at m[*p]: advance *p past it (to end on
 * overrun, so the caller's loop stops) and report whether it matches via
 * is_match. Shared walk for quic_salpn_select_h3/_select_hq -- only the
 * match predicate differs. */
typedef int (*quic_alpn_match_fn)(const u8*, usz);

static int salpn_entry_matches(
    const u8* m, usz end, usz* p, quic_alpn_match_fn is_match) {
  usz       nlen = m[*p];
  const u8* name = m + *p + 1;
  if (*p + 1 + nlen > end) {
    *p = end;
    return 0;
  }
  *p += 1 + nlen;
  return is_match(name, nlen);
}

/* ProtocolNameList end offset, or 0 if len is too small or the length field
 * overruns len (so the caller's loop never runs). */
static usz list_end(const u8* m, usz len) {
  usz end;
  if (len < 2) return 0;
  end = 2 + ((usz)m[0] << 8 | m[1]);
  return end <= len ? end : 0;
}

/* Shared select loop: 1 if any entry in alpn_ext_data's ProtocolNameList
 * matches is_match, else 0. */
static int salpn_select(
    const u8* alpn_ext_data, usz len, quic_alpn_match_fn is_match) {
  usz p = 2, end = list_end(alpn_ext_data, len);
  int hit = 0;
  while (p < end) {
    hit = salpn_entry_matches(alpn_ext_data, end, &p, is_match);
    if (hit) p = end;
  }
  return hit;
}

int quic_salpn_select_h3(const u8* alpn_ext_data, usz len) {
  return salpn_select(alpn_ext_data, len, quic_tls_alpn_is_h3);
}

int quic_salpn_select_hq(const u8* alpn_ext_data, usz len) {
  return salpn_select(alpn_ext_data, len, quic_tls_alpn_is_hq);
}

quic_salpn_choice quic_salpn_negotiate(const u8* alpn_ext_data, usz len) {
  if (quic_salpn_select_h3(alpn_ext_data, len)) return QUIC_SALPN_H3;
  if (quic_salpn_select_hq(alpn_ext_data, len)) return QUIC_SALPN_HQ;
  return QUIC_SALPN_NONE;
}

/* Append name (nlen bytes) as a 1-byte-length-prefixed ProtocolNameList
 * entry inside the fixed EncryptedExtensions ALPN extension shape (header
 * + ext_data_len + list_len + name_len + name). Returns 1 if it fit. */
static int build_alpn_ext(
    const u8* name, u8 nlen, u8* out, usz cap, usz* out_len) {
  usz total = 6 + 1 + (usz)nlen;
  if (cap < total) return 0;
  out[0] = 0x00;
  out[1] = 0x10; /* extension_type = ALPN */
  out[2] = 0x00;
  out[3] =
      (u8)(3 + nlen); /* extension_data length: list_len(2)+name_len(1)+name */
  out[4] = 0x00;
  out[5] = (u8)(1 + nlen); /* ProtocolNameList length: name_len(1)+name */
  out[6] = nlen;           /* name length */
  for (usz i = 0; i < nlen; i++) out[7 + i] = name[i];
  *out_len = total;
  return 1;
}

int quic_salpn_build_response(
    quic_salpn_choice choice, u8* out, usz cap, usz* out_len) {
  static const u8 h3[2]  = {0x68, 0x33};
  static const u8 hq[10] = {0x68, 0x71, 0x2d, 0x69, 0x6e,
                            0x74, 0x65, 0x72, 0x6f, 0x70};
  if (choice == QUIC_SALPN_H3) return build_alpn_ext(h3, 2, out, cap, out_len);
  if (choice == QUIC_SALPN_HQ) return build_alpn_ext(hq, 10, out, cap, out_len);
  return 0;
}
