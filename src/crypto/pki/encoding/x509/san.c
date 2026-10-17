/* RFC 5280 4.2.1.6. GeneralName dNSName is [2] IMPLICIT IA5String. */

/* RFC 5280 4.2.1.6. GeneralName iPAddress is [7] IMPLICIT OCTET STRING. */

/* An IPv4 address in its 4-octet form. */

#include "crypto/pki/encoding/x509/san_impl.h"

static int dns_eq(wired_span a, wired_span b);
static usz first_dot(wired_span name);
static usz wildcard_star(wired_span label);
static int label_wildcard_match(wired_span label, wired_span hlabel, usz star);
static int is_wildcard(wired_span entry);
static int wildcard_applicable(wired_span entry, usz hdot, usz host_n);
static int wildcard_match(wired_span entry, wired_span host);

/* id-ce-subjectAltName = 2.5.29.17 */
const u8 oid_san[] = {0x55, 0x1d, 0x11};

/* RFC 5280 A.1. id-at-commonName = 2.5.4.3. */
const u8 san_oid_cn[] = {0x55, 0x04, 0x03};

/* RFC 6125 6.4.1: hostname comparison is ASCII case-insensitive. */
static int dns_eq(wired_span a, wired_span b) { return ascii_dns_eq(a, b); }

/* Offset of the first '.' in name, or its length if none. */
static usz first_dot(wired_span name) {
  usz i = 0;
  while (i < name.n && name.p[i] != '.') {
    i++;
  }
  return i;
}

/* Offset of '*' within the left-most label of entry, or entry.n's first-dot
 * offset if the label carries none. */
static usz wildcard_star(wired_span label) {
  usz i = 0;
  while (i < label.n && label.p[i] != '*') {
    i++;
  }
  return i;
}

/* RFC 6125 6.4.3 rule 2 (MAY): the left-most label matches host's left-most
 * label when it is prefix + '*' + suffix, i.e. host's label starts with
 * prefix, ends with suffix, and is at least as long as prefix+suffix
 * combined (the '*' may cover zero or more characters). */
static int label_wildcard_match(wired_span label, wired_span hlabel, usz star) {
  wired_span prefix = wired_span_of(label.p, star);
  wired_span suffix = wired_span_of(label.p + star + 1, label.n - star - 1);
  if (hlabel.n < prefix.n + suffix.n) {
    return 0;
  }
  return dns_eq(prefix, wired_span_of(hlabel.p, prefix.n)) &&
         dns_eq(
             suffix, wired_span_of(hlabel.p + hlabel.n - suffix.n, suffix.n));
}

/* RFC 6125 6.4.3. entry's left-most label contains a '*' (rule 2's fragment
 * wildcard covers the plain "*." case too, star at offset 0). */
static int is_wildcard(wired_span entry) {
  usz ldot = first_dot(entry);
  return ldot < entry.n && wildcard_star(wired_span_of(entry.p, ldot)) < ldot;
}

/* entry carries a fragment wildcard and host actually has a label to match
 * it against (a bare hostname with no '.' has no remainder to compare). */
static int wildcard_applicable(wired_span entry, usz hdot, usz host_n) {
  return is_wildcard(entry) && hdot < host_n;
}

/* RFC 6125 6.4.3. entry's left-most label, possibly containing one '*'
 * fragment wildcard, matches host's left-most label and the remainders
 * (from the first '.' on) are equal. */
static int wildcard_match(wired_span entry, wired_span host) {
  usz edot = first_dot(entry);
  usz hdot = first_dot(host);
  usz star = wildcard_star(wired_span_of(entry.p, edot));
  if (!wildcard_applicable(entry, hdot, host.n)) {
    return 0;
  }
  if (!label_wildcard_match(
          wired_span_of(entry.p, edot), wired_span_of(host.p, hdot), star)) {
    return 0;
  }
  return dns_eq(
      wired_span_of(entry.p + edot, entry.n - edot),
      wired_span_of(host.p + hdot, host.n - hdot));
}

/* One GeneralName dNSName entry matches the hostname. */
int x509_entry_matches(wired_span e, wired_span host) {
  return dns_eq(e, host) || wildcard_match(e, host);
}
