#include "tls/ext/salpn/negotiate.h"

#include "tls/handshake/core/tls/alpn_match.h"

/* RFC 7301 3.1. */

/* One ProtocolNameList entry at m[*p]: advance *p past it (to end on
 * overrun, so the caller's loop stops) and report whether it matches via
 * is_match. Shared walk for salpn_select_h3/_select_hq -- only the
 * match predicate differs. */
typedef int (*alpn_match_fn)(const u8*, usz);

static int salpn_entry_matches(
    const u8* m, usz end, usz* p, alpn_match_fn is_match) {
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
    const u8* alpn_ext_data, usz len, alpn_match_fn is_match) {
  usz p = 2, end = list_end(alpn_ext_data, len);
  int hit = 0;
  while (p < end) {
    hit = salpn_entry_matches(alpn_ext_data, end, &p, is_match);
    if (hit) p = end;
  }
  return hit;
}

int salpn_select_h3(const u8* alpn_ext_data, usz len) {
  return salpn_select(alpn_ext_data, len, tls_alpn_is_h3);
}

int salpn_select_hq(const u8* alpn_ext_data, usz len) {
  return salpn_select(alpn_ext_data, len, tls_alpn_is_hq);
}

/* The protocol this server speaks under `name`, or SALPN_NONE. */
static salpn_choice salpn_name_choice(const u8* name, usz nlen) {
  if (tls_alpn_is_h3(name, nlen)) return SALPN_H3;
  return tls_alpn_is_hq(name, nlen) ? SALPN_HQ : SALPN_NONE;
}

/* The choice for the ProtocolNameList entry at m[*p], advancing *p past it
 * (to end on overrun, stopping the caller's loop). */
static salpn_choice salpn_entry_choice(const u8* m, usz end, usz* p) {
  usz       nlen = m[*p];
  const u8* name = m + *p + 1;
  if (*p + 1 + nlen > end) {
    *p = end;
    return SALPN_NONE;
  }
  *p += 1 + nlen;
  return salpn_name_choice(name, nlen);
}

/* RFC 7301 3.1: ProtocolNameList is in the client's preference order --
 * select the FIRST entry this server speaks, not a server-side favorite.
 * (msquic offers [hq-interop, h3, ...] and then talks hq-interop; answering
 * h3 made it send a bare GET line into an h3 connection.) */
salpn_choice salpn_negotiate(const u8* alpn_ext_data, usz len) {
  usz p = 2, end = list_end(alpn_ext_data, len);
  while (p < end) {
    salpn_choice c = salpn_entry_choice(alpn_ext_data, end, &p);
    if (c != SALPN_NONE) return c;
  }
  return SALPN_NONE;
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

static const u8 salpn_h3_name[2]  = {0x68, 0x33};
static const u8 salpn_hq_name[10] = {0x68, 0x71, 0x2d, 0x69, 0x6e,
                                     0x74, 0x65, 0x72, 0x6f, 0x70};

wired_span salpn_choice_name(salpn_choice choice, wired_span tok) {
  wired_span names[] = {{0, 0}, {salpn_h3_name, 2}, {salpn_hq_name, 10}, tok};
  return (usz)choice < 4 ? names[choice] : wired_span_of(0, 0);
}

/* A ProtocolName is 1..255 bytes (RFC 7301 3.1: opaque <1..2^8-1>). */
static int salpn_name_fits(wired_span name) {
  return name.n != 0 && name.n <= 0xff;
}

int salpn_build_response_tok(wired_span name, wired_obuf* out) {
  usz n = 0;
  if (!salpn_name_fits(name)) return 0;
  if (!build_alpn_ext(
          name.p, (u8)name.n, out->p + out->len, out->cap - out->len, &n))
    return 0;
  out->len += n;
  return 1;
}

int salpn_build_response(salpn_choice choice, u8* out, usz cap, usz* out_len) {
  wired_obuf ob = obuf_of(out, cap);
  if (!salpn_build_response_tok(
          salpn_choice_name(choice, wired_span_of(0, 0)), &ob))
    return 0;
  *out_len = ob.len;
  return 1;
}
