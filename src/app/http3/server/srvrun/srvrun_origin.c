#include "app/http3/server/srvrun/srvrun_origin.h"

#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/x509.h"

static wired_span srvrun_origin_authority(const wired_h3reqdrive_req* r);
static int        srvrun_origin_port_ok(wired_span a, usz i);
static int        srvrun_origin_literal_ok(wired_span a, usz i, wired_span h);
static int        srvrun_origin_ip_literal(wired_span a, wired_span* host);
static int        srvrun_origin_host(wired_span a, wired_span* host);
static int        srvrun_origin_is_https(const wired_h3reqdrive_req* r);
static int srvrun_origin_skip(const srvrun_conn* c, int ok, wired_span h);
static int srvrun_origin_leaf_covers(const srvrun_conn* c, wired_span h);
static int srvrun_origin_covered(const srvrun_conn* c, wired_span a);
static u16 srvrun_origin_421(const srvrun_conn* c);

/* RFC 9110 7.2 / RFC 9114 4.3.1: the target authority, :authority first,
 * else the Host field (the two match when both are present). */
static wired_span srvrun_origin_authority(const wired_h3reqdrive_req* r) {
  wired_span a = wired_span_of(r->authority, r->authority_len);
  if (!r->authority) {
    wired_http_req_header(r, wired_span_of((const u8*)"host", 4), &a);
  }
  return a;
}

/* a[i] is the closing "]", followed by nothing or by ":" port. */
static int srvrun_origin_port_ok(wired_span a, usz i) {
  return i < a.n && (i + 1 == a.n || a.p[i + 1] == ':');
}

/* The bracket contents h are IPv6-shaped (a ':'); IPvFuture, a DNS name
 * or an IPv4 address between brackets is no IPv6address. */
static int srvrun_origin_literal_ok(wired_span a, usz i, wired_span h) {
  return srvrun_origin_port_ok(a, i) && bytes_find(h, 0, ':') < h.n;
}

/* RFC 3986 3.2.2: IP-literal = "[" IPv6address "]" (IPvFuture is not
 * served). *host is the address between the brackets; 0 when the literal
 * is malformed (unclosed, not IPv6-shaped, or junk after "]"). */
static int srvrun_origin_ip_literal(wired_span a, wired_span* host) {
  usz i = bytes_find(a, 0, ']');
  *host = wired_span_of(a.p + 1, i - 1);
  return srvrun_origin_literal_ok(a, i, *host);
}

/* RFC 3986 3.2.2: authority minus its ":port"; 0 on a malformed
 * IP-literal. */
static int srvrun_origin_host(wired_span a, wired_span* host) {
  if (a.n && a.p[0] == '[') {
    return srvrun_origin_ip_literal(a, host);
  }
  *host = wired_span_of(a.p, bytes_find(a, 0, ':'));
  return 1;
}

static int srvrun_origin_is_https(const wired_h3reqdrive_req* r) {
  return r->scheme_len == 5 && ct_diffn(r->scheme, (const u8*)"https", 5) == 0;
}

/* Nothing to compare: no certificate (raw test connections) or a
 * well-formed authority with no host. */
static int srvrun_origin_skip(const srvrun_conn* c, int ok, wired_span h) {
  return !c->s.sdrv.cert_count || (ok && !h.n);
}

/* RFC 9110 4.3.4 / RFC 9525: the leaf certificate this connection was
 * secured with covers host h. */
static int srvrun_origin_leaf_covers(const srvrun_conn* c, wired_span h) {
  x509 leaf;
  return x509_parse(c->s.sdrv.certs[0], &leaf) && x509_san_matches(leaf.tbs, h);
}

/* Authority a is covered. A malformed IP-literal is fail-closed (421)
 * rather than a 400 or an RFC 9114 4.1.2 malformed-message reset, which
 * would belong in the h3reqdrive authority check. */
static int srvrun_origin_covered(const srvrun_conn* c, wired_span a) {
  wired_span h;
  int        ok = srvrun_origin_host(a, &h);
  if (srvrun_origin_skip(c, ok, h)) {
    return 1;
  }
  return ok && srvrun_origin_leaf_covers(c, h);
}

static u16 srvrun_origin_421(const srvrun_conn* c) {
  return srvrun_origin_covered(c, srvrun_origin_authority(&c->l.req)) ? 0 : 421;
}

/* RFC 9110 7.4 / 15.5.20 (9110-037): an https request whose origin the
 * connection's certificate is not valid for is answered 421 (Misdirected
 * Request) instead of reaching the application. status is the one already
 * chosen (non-zero wins). */
u16 srvrun_origin_status(const srvrun_conn* c, u16 status) {
  if (status || !srvrun_origin_is_https(&c->l.req)) {
    return status;
  }
  return srvrun_origin_421(c);
}
