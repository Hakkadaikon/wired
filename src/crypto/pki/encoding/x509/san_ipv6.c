#include "crypto/pki/encoding/x509/san_impl.h"

static int san6_is_dcolon(wired_span s, usz i);
static usz san6_dcolon(wired_span s);
static int san6_halves(wired_span s, usz dc, u8* out, u8* t, usz n[2]);
static int san6_split(wired_span s, usz dc, u8 out[SAN_IPV6_LEN]);
static int san6_full(wired_span s, u8 out[SAN_IPV6_LEN]);

static int san6_is_dcolon(wired_span s, usz i) {
  return s.p[i] == ':' && s.p[i + 1] == ':';
}

/* Offset of the first "::" in s, or s.n. */
static usz san6_dcolon(wired_span s) {
  for (usz i = 0; i + 1 < s.n; i++) {
    if (san6_is_dcolon(s, i)) {
      return i;
    }
  }
  return s.n;
}

/* RFC 4291 2.2 form 2: "::" appears once; the pieces before it go to out
 * (n[0] octets), those after it (IPv4 tail allowed) to t (n[1]). */
static int san6_halves(wired_span s, usz dc, u8* out, u8* t, usz n[2]) {
  wired_span tail = wired_span_of(s.p + dc + 2, s.n - dc - 2);
  return san6_dcolon(tail) == tail.n &&
         san6_list(wired_span_of(s.p, dc), out, &n[0], 0) &&
         san6_list(tail, t, &n[1], 1);
}

/* "::" stands for one or more zero groups, so at most 7 groups remain. */
static int san6_split(wired_span s, usz dc, u8 out[SAN_IPV6_LEN]) {
  u8  t[SAN_IPV6_LEN];
  usz n[2];
  if (!san6_halves(s, dc, out, t, n)) {
    return 0;
  }
  if (n[0] + n[1] > SAN_IPV6_LEN - 2) {
    return 0;
  }
  bytes_memcpy(out + SAN_IPV6_LEN - n[1], t, n[1]);
  return 1;
}

/* RFC 4291 2.2 forms 1 and 3 without "::": all 16 octets spelled out. */
static int san6_full(wired_span s, u8 out[SAN_IPV6_LEN]) {
  usz n;
  return san6_list(s, out, &n, 1) && n == SAN_IPV6_LEN;
}

/* RFC 4291 2.2 text -> 16 octets. Accepts any of its forms (RFC 5952
 * canonical form is not required on input). Brackets (RFC 3986 3.2.2) are
 * the caller's to strip; an RFC 6874 zone ID ("%25...") is rejected, since
 * a zone is local to its host and no iPAddress entry can carry one. */
int san_ipv6_parse(wired_span host, u8 out[SAN_IPV6_LEN]) {
  usz dc = san6_dcolon(host);
  bytes_memset(out, 0, SAN_IPV6_LEN);
  if (dc == host.n) {
    return san6_full(host, out);
  }
  return san6_split(host, dc, out);
}

/* A ':' marks an IPv6 reference identity (RFC 4291 2.2). */
int san_ipv6_shaped(wired_span host) {
  return bytes_find(host, 0, ':') < host.n;
}
