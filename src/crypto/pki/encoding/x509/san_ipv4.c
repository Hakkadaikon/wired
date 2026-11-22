#include "crypto/pki/encoding/x509/san_impl.h"

static int  octet_len_ok(wired_span d);
static int  no_leading_zero(wired_span d);
static int  octet_digits_shape_ok(wired_span d);
static int  digits_value(wired_span d, u32* out);
static int  octet_digits_value(wired_span d, u32* out);
static int  ipv4_octet(wired_span s, usz* off, u8* out);
static int  ip_entry_matches(wired_span e, wired_span want);
static void names_match_one(
    u8 tag, wired_span e, wired_span host, int* found_id, int* match);

/* d.n is a valid octet digit-run length: 1 to 3 octets. */
static int octet_len_ok(wired_span d) { return d.n >= 1 && d.n <= 3; }

/* d has no leading '0' unless d is the single digit "0". */
static int no_leading_zero(wired_span d) { return d.n == 1 || d.p[0] != '0'; }

/* d.n in [1,3], and no leading '0' unless d is the single digit "0". */
static int octet_digits_shape_ok(wired_span d) {
  if (!octet_len_ok(d)) {
    return 0;
  }
  return no_leading_zero(d);
}

/* Decimal value of d's digits, requiring every octet to be a digit.
 * Returns 1 ok, 0 on a non-digit. */
static int digits_value(wired_span d, u32* out) {
  u32 v = 0;
  for (usz i = 0; i < d.n; i++) {
    int dv = ascii_dec(d.p[i]);
    if (dv < 0) {
      return 0;
    }
    v = v * 10 + (u32)dv;
  }
  *out = v;
  return 1;
}

/* Decimal value of one octet's digits (span.n in [1,3]), rejecting a leading
 * '0' on any but a single "0" digit, and any non-digit. Returns 1 ok. */
static int octet_digits_value(wired_span d, u32* out) {
  if (!octet_digits_shape_ok(d)) {
    return 0;
  }
  return digits_value(d, out);
}

/* One dot-separated IPv4 octet starting at *off, ending at a '.' or the
 * span's end. Advances *off one past that end, as if a '.' always followed,
 * so the whole text is consumed exactly when *off reaches s.n + 1 (a
 * trailing '.' after the fourth octet leaves it at s.n). Returns 1 ok, 0
 * if the digits are malformed or out of range. */
static int ipv4_octet(wired_span s, usz* off, u8* out) {
  usz start = *off;
  usz end   = bytes_find(s, start, '.');
  u32 v;
  if (!octet_digits_value(wired_span_of(s.p + start, end - start), &v)) {
    return 0;
  }
  if (v > 255) {
    return 0;
  }
  *off = end + 1;
  *out = (u8)v;
  return 1;
}

/* RFC 791 3.1-shaped dotted-decimal text -> 4 octets. Rejects a leading zero
 * on any octet wider than one digit, out-of-range octets, and anything not
 * exactly 4 dot-separated octets (a DNS name or an IPv6 literal included). */
int san_ipv4_parse(wired_span host, u8 out[SAN_IPV4_LEN]) {
  usz off = 0;
  for (usz i = 0; i < SAN_IPV4_LEN; i++) {
    if (!ipv4_octet(host, &off, &out[i])) {
      return 0;
    }
  }
  return off == host.n + 1;
}

/* RFC 9525 6.3: one GeneralName iPAddress entry (raw octets, 4 for IPv4,
 * 16 for IPv6 per RFC 5280 4.2.1.6) equals the parsed reference identity
 * octet for octet; a length mismatch never matches. */
static int ip_entry_matches(wired_span e, wired_span want) {
  return e.n == want.n && ct_diffn(e.p, want.p, want.n) == 0;
}

/* RFC 5280 4.2.1.6. The GeneralNames SEQUENCE value inside the extnValue. */
int san_names(wired_span tbs, wired_span* names) {
  wired_span san;
  if (!x509_find_ext(tbs, wired_span_of(oid_san, sizeof(oid_san)), &san)) {
    return 0;
  }
  return der_seq(san, names);
}

/* One GeneralNames element: if it is a DNS-ID, URI-ID or SRV-ID, records
 * that (*found_id = 1); a dNSName also folds its match outcome into
 * *match. */
static void names_match_one(
    u8 tag, wired_span e, wired_span host, int* found_id, int* match) {
  *found_id |= san_presented_id(tag, e);
  if (tag != SAN_DNSNAME_TAG) {
    return;
  }
  if (x509_entry_matches(e, host)) {
    *match = 1;
  }
}

/* RFC 5280 4.2.1.6 / RFC 6125 6.4.4: scan the GeneralNames. found_id is
 * set to 1 if any DNS-ID, URI-ID or SRV-ID is present at all (regardless of
 * match) -- that alone rules out the RFC 6125 6.4.4 CN-ID fallback, matched
 * entries or not. Returns 1 on a matching dNSName. */
int x509_names_match(wired_span gn, wired_span host, int* found_id) {
  derseq     names;
  u8         tag;
  wired_span e;
  int        match = 0;
  derseq_init(&names, gn);
  while (derseq_next(&names, &tag, &e)) {
    names_match_one(tag, e, host, found_id, &match);
  }
  return match;
}

/* One GeneralNames element is an iPAddress entry matching want. */
int x509_ip_names_one(u8 tag, wired_span e, wired_span want) {
  return tag == SAN_IPADDR_TAG && ip_entry_matches(e, want);
}
