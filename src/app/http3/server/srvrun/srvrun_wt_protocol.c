#include "app/http3/server/srvrun/srvrun_impl.h"

static int  srvrun_http_head_ok(const wired_http_exchange* x);
static int  srvrun_http_ok(const wired_http_exchange* x);
static void srvrun_http_drop_content(wired_http_exchange* x);
static void srvrun_http_reject(wired_http_exchange* x);
static int  wt_protocol_token_eq(
    const wired_h3reqdrive_req* r, const u8* want, usz n);
static int wt_protocol_is_webtransport(const wired_h3reqdrive_req* r);
static int wt_method_is_connect(const wired_h3reqdrive_req* r);
static int wt_ext_fields_present(const wired_h3reqdrive_req* r);
static int wt_ext_connect_shape_ok(const wired_h3reqdrive_req* r);
static int wt_origin_app_ok(
    const srvrun_cfg* cfg, const wired_h3reqdrive_req* r);

static int srvrun_http_head_ok(const wired_http_exchange* x) {
  return srvrun_http_status_final(x->status) &&
         x->field_count <= WIRED_HTTP_MAX_FIELDS;
}

static int srvrun_http_ok(const wired_http_exchange* x) {
  return srvrun_http_head_ok(x) && srvrun_http_ct_ok(x->content_type) &&
         srvrun_http_fields_ok(x);
}

/* No content: no body, no further rounds, no content-type. */
static void srvrun_http_drop_content(wired_http_exchange* x) {
  x->body->len    = 0;
  x->more         = 0;
  x->total_size   = 0;
  x->content_type = 0;
}

/* RFC 9110 15.6 / 15.6.1: the application produced an unsendable
 * response -- answer a 500 instead, explained in a short text/plain body
 * (none for HEAD, srvrun_status_body). */
static void srvrun_http_reject(wired_http_exchange* x) {
  wired_span text;
  usz        off = 0;
  x->status      = 500;
  x->field_count = 0;
  srvrun_http_drop_content(x);
  text = srvrun_status_body(x->req, x->status);
  if (!bytes_put(wired_mspan_of(x->body->p, x->body->cap), &off, text)) {
    return;
  }
  x->body->len    = off;
  x->content_type = text.n ? "text/plain" : 0;
}

/* x's status: 0 (every 7-argument handler's) means 200. */
u16 srvrun_http_status(const wired_http_exchange* x) {
  return (u16)(x->status + 200 * (x->status == 0));
}

/* Settle round 0 of a wired_http_handler response: 0 means 200, an invalid
 * status/field set becomes 500 (see wired_http_exchange), and a 204/304
 * loses its content. */
void srvrun_http_settle(wired_http_exchange* x) {
  x->status = srvrun_http_status(x);
  if (!srvrun_http_ok(x)) {
    srvrun_http_reject(x);
  }
  if (srvrun_http_status_bodiless(x->status)) {
    srvrun_http_drop_content(x);
  }
}

/* All len octets of m equal want (draft-ietf-webtrans-http3-15 SS3: the
 * :protocol value is matched byte for byte, same idiom as connect.c's own
 * method_is_connect). */
int srvrun_wt_bytes_eq(const u8* m, const u8* want, usz len) {
  for (usz i = 0; i < len; i++) {
    if (m[i] != want[i]) {
      return 0;
    }
  }
  return 1;
}

/* r's :protocol equals the n-octet token want. */
static int wt_protocol_token_eq(
    const wired_h3reqdrive_req* r, const u8* want, usz n) {
  if (!r->protocol || r->protocol_len != n) {
    return 0;
  }
  return srvrun_wt_bytes_eq(r->protocol, want, n);
}

/* r's :protocol is a WebTransport token: "webtransport" (what every deployed
 * browser generation -- Chrome 149 included, a draft-07 implementation --
 * actually sends) or "webtransport-h3" (draft-ietf-webtrans-http3-15 SS3's
 * renamed token). Accepting only the draft-15 spelling turned away every
 * real browser. */
static int wt_protocol_is_webtransport(const wired_h3reqdrive_req* r) {
  static const u8 d7[]  = {'w', 'e', 'b', 't', 'r', 'a',
                           'n', 's', 'p', 'o', 'r', 't'};
  static const u8 d15[] = {'w', 'e', 'b', 't', 'r', 'a', 'n', 's',
                           'p', 'o', 'r', 't', '-', 'h', '3'};
  if (wt_protocol_token_eq(r, d7, sizeof d7)) {
    return 1;
  }
  return wt_protocol_token_eq(r, d15, sizeof d15);
}

/* :method value equals the 7 octets "CONNECT" (same idiom as connect.c's own
 * method_is_connect, duplicated here because that one is private to
 * connect.c and connect_forbidden's shape does not fit Extended CONNECT
 * below). */
static int wt_method_is_connect(const wired_h3reqdrive_req* r) {
  static const u8 want[] = {'C', 'O', 'N', 'N', 'E', 'C', 'T'};
  if (!r->method || r->method_len != sizeof want) {
    return 0;
  }
  return srvrun_wt_bytes_eq(r->method, want, sizeof want);
}

/* r carries :scheme, :authority and :path, all required (non-forbidden) for
 * Extended CONNECT unlike plain CONNECT (RFC 9220 3 / RFC 9114 4.4 contrast:
 * h3_connect_req_ok enforces the opposite, plain-CONNECT shape, so it
 * cannot be reused here). */
static int wt_ext_fields_present(const wired_h3reqdrive_req* r) {
  return r->scheme != 0 && r->authority != 0 && r->path != 0;
}

/* r's request line is CONNECT with :scheme/:authority/:path all present:
 * the Extended CONNECT shape, checked before :protocol. */
static int wt_ext_connect_shape_ok(const wired_h3reqdrive_req* r) {
  if (!wt_method_is_connect(r)) {
    return 0;
  }
  return wt_ext_fields_present(r);
}

/* r is a well-formed Extended CONNECT (RFC 9220 3) for WebTransport:
 * :method=CONNECT, :scheme/:authority/:path all present, :protocol
 * negotiated (settings always advertised, Step 1 above) and a WebTransport
 * token (see wt_protocol_is_webtransport). */
int srvrun_is_wt_connect(const wired_h3reqdrive_req* r) {
  if (!wt_ext_connect_shape_ok(r)) {
    return 0;
  }
  if (!wt_protocol_is_webtransport(r)) {
    return 0;
  }
  return h3_connect_protocol_ok(r, 1);
}

/* RFC 9220 3: "If a server advertises support for Extended CONNECT but
 * receives an Extended CONNECT request with a :protocol value that is
 * unknown or is not supported, the server SHOULD respond ... with a 501
 * (Not Implemented) status code." r is exactly that case: the Extended
 * CONNECT shape (:method=CONNECT, :scheme/:authority/:path all present) with
 * a :protocol field present that names something other than a recognized
 * WebTransport token. srvrun_is_wt_connect already rejects this same r (its
 * wt_protocol_is_webtransport check fails), so without this check r would
 * fall through to srvrun_method_status/srvrun_start_app_resp and be treated
 * as an ordinary CONNECT request -- wrong, since RFC 9220's 501 applies the
 * moment :protocol names something this server does not support, before any
 * plain-CONNECT handling. A CONNECT with no :protocol at all (plain CONNECT,
 * RFC 9114 4.4) is unaffected: r->protocol is 0 there, so this returns 0 and
 * the normal method-status/app-handler path still runs. */
int srvrun_is_wt_connect_unsupported_protocol(const wired_h3reqdrive_req* r) {
  if (!wt_ext_connect_shape_ok(r)) {
    return 0;
  }
  if (!r->protocol) {
    return 0;
  }
  return !wt_protocol_is_webtransport(r);
}

/* draft-ietf-webtrans-http3-15 SS3.1: the app's own Origin verdict
 * (wired_srvrun_opt.wt_origin_check), 1 when none is registered. An absent
 * origin header reaches the callback as an empty span. */
static int wt_origin_app_ok(
    const srvrun_cfg* cfg, const wired_h3reqdrive_req* r) {
  if (!cfg->wt_origin_check) {
    return 1;
  }
  return cfg->wt_origin_check(
             cfg->wt_origin_ctx, wired_span_of(r->origin, r->origin_len),
             wired_span_of(r->authority, r->authority_len)) != 0;
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.6: when Origin is present it
 * must be a non-empty value for the server to validate; past that, the app's
 * registered wt_origin_check (if any) decides. Absent Origin is not itself a
 * rejection reason: it only applies to browser clients, which this SDK
 * cannot detect server-side. */
int srvrun_wt_origin_ok(const srvrun_cfg* cfg, const wired_h3reqdrive_req* r) {
  if (r->origin && !r->origin_len) {
    return 0; /* present but empty */
  }
  return wt_origin_app_ok(cfg, r);
}
