#include "app/http3/request/h3reqdrive/request_drive_impl.h"

static int path_present_and_empty(const wired_h3reqdrive_req* r);
static int rd_hdr_name_is(
    const wired_h3reqdrive_req* req,
    const wired_h3reqdrive_hdr* h,
    wired_span                  name);
static int rd_hdrs_find(
    const wired_h3reqdrive_req* req, wired_span name, wired_span* out);
static int rd_dedicated_found(
    const wired_h3reqdrive_req* req, usz i, wired_span* out);

/* RFC 9114 4.3.1: a :path pseudo-header that was present (r->path != 0, so
 * CONNECT's legitimate omission is unaffected) but empty is malformed --
 * "*" (OPTIONS' asterisk-form, RFC 9114 4.3.1/9114-027) is one octet and
 * never trips this. */
static int path_present_and_empty(const wired_h3reqdrive_req* r) {
  return r->path != 0 && r->path_len == 0;
}

/* RFC 9114 4.1, RFC 9204 4.5 */
int wired_h3reqdrive_recv_get_dyn(
    wired_span            stream_data,
    wired_mspan           scratch,
    const qpack_dyn*      dyn,
    wired_h3reqdrive_req* r) {
  wired_span fs = wired_span_of(0, 0);
  *r            = (wired_h3reqdrive_req){0};
  h3_priority_init(&r->priority);
  r->hdr_base = scratch.p;
  if (!wired_h3reqdrive_request_sections(stream_data, &fs, r)) {
    return 0;
  }
  if (!h3reqdrive_decode_sections(stream_data, fs, scratch, dyn, r)) {
    return 0;
  }
  return !path_present_and_empty(r);
}

/* RFC 9114 4.1, RFC 9204 4.5: static-table-only convenience wrapper (no
 * dynamic table observed / not tracked by this caller). */
int wired_h3reqdrive_recv_get(
    wired_span stream_data, wired_mspan scratch, wired_h3reqdrive_req* r) {
  return wired_h3reqdrive_recv_get_dyn(stream_data, scratch, 0, r);
}

static int rd_hdr_name_is(
    const wired_h3reqdrive_req* req,
    const wired_h3reqdrive_hdr* h,
    wired_span                  name) {
  return h->name_len == name.n &&
         ct_diffn(req->hdr_base + h->name_off, name.p, name.n) == 0;
}

static int rd_hdrs_find(
    const wired_h3reqdrive_req* req, wired_span name, wired_span* out) {
  for (usz i = 0; i < req->hdr_count; i++) {
    const wired_h3reqdrive_hdr* h = &req->hdrs[i];
    if (!rd_hdr_name_is(req, h, name)) {
      continue;
    }
    *out = wired_span_of(req->hdr_base + h->value_off, h->value_len);
    return 1;
  }
  return 0;
}

/* The dedicated field behind rd_dedicated[i]; empty means absent. */
static int rd_dedicated_found(
    const wired_h3reqdrive_req* req, usz i, wired_span* out) {
  wired_span v[RD_DEDICATED_N] = {
      wired_span_of(req->cookie, req->cookie_len),
      wired_span_of(req->origin, req->origin_len),
      wired_span_of(req->wt_avail, req->wt_avail_len)};
  if (!v[i].n) {
    return 0;
  }
  *out = v[i];
  return 1;
}

/* RFC 9114 4.2 */
int wired_http_req_header(
    const wired_h3reqdrive_req* req, wired_span name, wired_span* out) {
  usz d = h3reqdrive_rd_dedicated_idx(name);
  if (d < RD_DEDICATED_N) {
    return rd_dedicated_found(req, d, out);
  }
  return rd_hdrs_find(req, name, out);
}
