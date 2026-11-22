#include "common/bytes/util/be.h"
#include "crypto/pki/encoding/x509/san_impl.h"

/* RFC 4291 2.2: the ':'-separated pieces of an IPv6 text address, for
 * san_ipv6.c, which handles the "::" split. */

static int san6_hex(u8 c);
static int san6_hex_value(wired_span g, u32* out);
static int san6_group(wired_span g, u8* out);
static int san6_room(usz n, usz k);
static int san6_put16(wired_span g, u8* out, usz* n);
static int san6_put4(wired_span g, u8* out, usz* n);
static int san6_put(wired_span g, u8* out, usz* n, int v4);
static int san6_piece(wired_span s, usz* off, u8* out, usz* n, int v4);

/* One ASCII hex digit's value (either case), or -1. */
static int san6_hex(u8 c) {
  u8 l = ascii_lower(c);
  return (l >= 'a' && l <= 'f') ? l - 'a' + 10 : ascii_dec(c);
}

/* Value of g's hex digits; 0 on a non-hex octet. */
static int san6_hex_value(wired_span g, u32* out) {
  u32 v = 0;
  for (usz i = 0; i < g.n; i++) {
    int d = san6_hex(g.p[i]);
    if (d < 0) {
      return 0;
    }
    v = v * 16 + (u32)d;
  }
  *out = v;
  return 1;
}

/* RFC 4291 2.2 form 1: one 16-bit piece, 1 to 4 hex digits, into 2 octets. */
static int san6_group(wired_span g, u8* out) {
  u32 v;
  if (g.n - 1 > 3) {
    return 0;
  }
  if (!san6_hex_value(g, &v)) {
    return 0;
  }
  be_put_be16(out, (u16)v);
  return 1;
}

/* k more octets fit after the n already written. */
static int san6_room(usz n, usz k) { return n + k <= SAN_IPV6_LEN; }

static int san6_put16(wired_span g, u8* out, usz* n) {
  if (!san6_room(*n, 2) || !san6_group(g, out + *n)) {
    return 0;
  }
  *n += 2;
  return 1;
}

/* RFC 4291 2.2 form 3: the dotted-decimal low 32 bits. */
static int san6_put4(wired_span g, u8* out, usz* n) {
  if (!san6_room(*n, SAN_IPV4_LEN) || !san_ipv4_parse(g, out + *n)) {
    return 0;
  }
  *n += SAN_IPV4_LEN;
  return 1;
}

/* v4: g is the address's last piece, so it may be the IPv4 tail. */
static int san6_put(wired_span g, u8* out, usz* n, int v4) {
  if (v4 && bytes_find(g, 0, '.') < g.n) {
    return san6_put4(g, out, n);
  }
  return san6_put16(g, out, n);
}

/* The ':'-terminated piece at *off; *off moves past its ':'. */
static int san6_piece(wired_span s, usz* off, u8* out, usz* n, int v4) {
  usz end = bytes_find(s, *off, ':');
  if (!san6_put(
          wired_span_of(s.p + *off, end - *off), out, n, v4 && end == s.n)) {
    return 0;
  }
  *off = end + 1;
  return 1;
}

/* A ':'-separated piece list into out, *n octets. An empty list has no
 * pieces; otherwise a leading, doubled or trailing ':' leaves an empty
 * piece, which san6_group rejects (the bound is s.n inclusive). */
int san6_list(wired_span s, u8* out, usz* n, int v4) {
  usz off = 0;
  *n      = 0;
  while (off < s.n + (s.n != 0)) {
    if (!san6_piece(s, &off, out, n, v4)) {
      return 0;
    }
  }
  return 1;
}
