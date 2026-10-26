#include "app/http3/server/srvrun/srvrun_origin.h"

#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/x509.h"

static wired_span srvrun_origin_authority(const wired_h3reqdrive_req* r);
static wired_span srvrun_origin_host(wired_span a);
static int        srvrun_origin_is_https(const wired_h3reqdrive_req* r);
static int        srvrun_origin_skip(const srvrun_conn* c, wired_span host);
static int        srvrun_origin_covered(const srvrun_conn* c, wired_span host);
static u16        srvrun_origin_421(const srvrun_conn* c);

/* RFC 9110 7.2 / RFC 9114 4.3.1: the target authority, :authority first,
 * else the Host field (the two match when both are present). */
static wired_span srvrun_origin_authority(const wired_h3reqdrive_req* r) {
  wired_span a = wired_span_of(r->authority, r->authority_len);
  if (!r->authority) {
    wired_http_req_header(r, wired_span_of((const u8*)"host", 4), &a);
  }
  return a;
}

/* RFC 3986 3.2.2: authority minus its ":port". */
static wired_span srvrun_origin_host(wired_span a) {
  usz i = 0;
  while (i < a.n && a.p[i] != ':') {
    i++;
  }
  return wired_span_of(a.p, i);
}

static int srvrun_origin_is_https(const wired_h3reqdrive_req* r) {
  return r->scheme_len == 5 && ct_diffn(r->scheme, (const u8*)"https", 5) == 0;
}

/* Nothing to compare: no certificate (raw test connections), no host, or
 * an IP-literal. shortcut: an IPv6 literal is not matched against
 * iPAddress SANs (x509_san_matches takes IPv4 only); upgrade when it is. */
static int srvrun_origin_skip(const srvrun_conn* c, wired_span host) {
  return !c->s.sdrv.cert_count || !host.n || host.p[0] == '[';
}

/* RFC 9110 4.3.4 / RFC 6125: the leaf certificate this connection was
 * secured with covers host. */
static int srvrun_origin_covered(const srvrun_conn* c, wired_span host) {
  x509 leaf;
  if (srvrun_origin_skip(c, host)) {
    return 1;
  }
  return x509_parse(c->s.sdrv.certs[0], &leaf) &&
         x509_san_matches(leaf.tbs, host);
}

static u16 srvrun_origin_421(const srvrun_conn* c) {
  wired_span host = srvrun_origin_host(srvrun_origin_authority(&c->l.req));
  return srvrun_origin_covered(c, host) ? 0 : 421;
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
