/* libFuzzer harness for the MoQT codecs (draft-ietf-moq-transport-18/19/22).
 * Input byte 0 picks the draft (byte % MOQVER_COUNT -> MOQVER_D22/D19/D18,
 * moqver.h); every version-dependent decoder below takes that id. The rest
 * of the input is read as: varints (SS1.4.1), Key-Value-Pairs (SS10.2), the
 * control-message envelope + the message codecs (SS10, incl. FETCH / namespace
 * / TRACK_STATUS / REQUEST_UPDATE), the data-stream decoders (SS11.4, subgroup
 * and fetch streams), and the session state machine (SS3.3) fed with the events
 * the decoded control stream produces, OBJECT_DATAGRAM (11.3.1, decode ->
 * encode -> decode round-trip) and the FETCH object cache driven by an op
 * stream. Not covered: moqtrun (app/moqt/run) -- it is the session runtime, not
 * a codec; it needs a hub, transport callbacks and peer state, so it belongs to
 * an end-to-end harness, not this one. Hosted build only — mirrors
 * tests/run.c's unity-include style, but this file itself may use the
 * standard library since it lives outside src/. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "app/moqt/cache/moqcache.c"
#include "app/moqt/ctl/moqctl.c"
#include "app/moqt/data/moqdata.c"
#include "app/moqt/dgram/moqdg.c"
#include "app/moqt/fetch/moqfetch.c"
#include "app/moqt/kvp/moqkvp.c"
#include "app/moqt/ns/moqns.c"
#include "app/moqt/sess/moqsess.c"
#include "app/moqt/tstat/moqtstat.c"
#include "app/moqt/ver/moqver.c"
#include "app/moqt/vi/moqvi.c"

/* Decode one control message body by its envelope type (SS10). */
static void fuzz_ctl_body(int ver, u64 type, wired_span body) {
  usz off = 0;
  if (type == MOQCTL_T_SETUP) {
    moqctl_setup m;
    moqctl_setup_take(body, &off, &m);
  } else if (type == MOQCTL_T_SUBSCRIBE) {
    moqctl_subscribe m;
    moqctl_subscribe_take(ver, body, &off, &m);
  } else if (type == MOQCTL_T_SUBSCRIBE_OK) {
    moqctl_subscribe_ok m;
    moqctl_subscribe_ok_take(ver, body, &off, &m);
  } else if (type == MOQCTL_T_PUBLISH) {
    moqctl_publish m;
    moqctl_publish_take(ver, body, &off, &m);
  } else if (type == MOQCTL_T_REQUEST_OK) {
    moqctl_request_ok m;
    moqctl_request_ok_take(ver, body, &off, &m);
  } else if (type == MOQCTL_T_REQUEST_ERROR) {
    moqctl_request_error m;
    if (moqctl_request_error_take(body, &off, &m) == MOQCTL_OK)
      moqctl_request_error_for(ver, m.error_code);
  } else if (type == MOQCTL_T_PUBLISH_DONE) {
    moqctl_publish_done m;
    if (moqctl_publish_done_take(body, &off, &m) == MOQCTL_OK)
      moqctl_publish_done_for(ver, m.status_code);
  } else if (type == MOQCTL_T_GOAWAY) {
    moqctl_goaway m;
    if (moqver_caps(ver) & MOQVER_CAP_GOAWAY_REQID)
      moqctl_goaway18_take(body, &off, &m);
    else
      moqctl_goaway_take(body, &off, &m);
  }
}

/* The FETCH / namespace / TRACK_STATUS / REQUEST_UPDATE bodies (10.9,
 * 10.12-10.18), one switch on the envelope type. */
static void fuzz_ctl_body_more(int ver, u64 type, wired_span body) {
  moqfetch_fetch    fetch;
  moqfetch_ok       fok;
  moqns_req         req;
  moqctl_ns         ns;
  moqctl_subscribe  ts;
  moqctl_request_ok tok;
  moqtstat_update   up;
  moqfetch_req      fr;
  switch (type) {
    case MOQFETCH_T_FETCH:
      moqfetch_fetch_take(ver, body, &fetch);
      if (moqver_caps(ver) & MOQVER_CAP_FETCH_BODY_V22)
        moqfetch_req22_take(body, &fr);
      else
        moqfetch_req19_take(ver, body, &fr);
      break;
    case MOQFETCH_T_FETCH_OK:
      moqfetch_ok_take(ver, body, &fok);
      break;
    case MOQNS_T_SUBSCRIBE_NAMESPACE:
      moqns_subscribe_take(ver, body, &req);
      break;
    case MOQNS_T_PUBLISH_NAMESPACE:
      moqns_publish_take(ver, body, &req);
      break;
    case MOQCTL_T_SUBSCRIBE_TRACKS:
      moqns_subscribe_tracks_take(ver, body, &req);
      break;
    case MOQNS_T_NAMESPACE:
    case MOQNS_T_NAMESPACE_DONE:
      moqns_suffix_take(body, &ns);
      break;
    case MOQTSTAT_T_TRACK_STATUS:
      moqtstat_take(ver, body, &ts);
      break;
    case MOQCTL_T_REQUEST_OK:
      moqtstat_ok_take(ver, body, &tok);
      break;
    case MOQTSTAT_T_REQUEST_UPDATE:
      moqtstat_update_take(ver, body, MOQCTL_PCTX_UPDATE_SUBSCRIPTION, &up);
      break;
  }
}

/* Walk the input as a control stream (SS10 envelope), feeding the session
 * state machine the event each outcome produces (SS3.3): the first SETUP
 * establishes, a decode violation or unknown type is a malformed-control
 * event, GOAWAY drives the shutdown path. */
static void fuzz_ctl_stream(int ver, wired_span in) {
  moqsess sess;
  moqsess_init(&sess);
  moqsess_step(&sess, MOQSESS_EV_SENT_SETUP);

  usz off = 0;
  for (;;) {
    u64        type;
    wired_span body;
    int        r = moqctl_peek_type(in, &off, &type, &body);
    if (r == MOQCTL_INSUFFICIENT) break;
    r = moqctl_type_ver(ver, r, &type);
    if (r != MOQCTL_OK && r != MOQCTL_KNOWN_UNIMPLEMENTED) {
      moqsess_step(&sess, MOQSESS_EV_MALFORMED_CTRL);
      break;
    }
    fuzz_ctl_body(ver, type, body);
    fuzz_ctl_body_more(ver, type, body);
    if (type == MOQCTL_T_SETUP) moqsess_step(&sess, MOQSESS_EV_RECV_SETUP);
    if (type == MOQCTL_T_GOAWAY) moqsess_step(&sess, MOQSESS_EV_RECV_GOAWAY);
    moqsess_should_buffer(&sess);
    moqsess_established(&sess);
    moqsess_may_reject_request(&sess);
  }
  moqsess_step(&sess, MOQSESS_EV_CTRL_CLOSED);
}

/* A fetch stream (11.4.4): FETCH_HEADER, then chained fetch Objects, once
 * per Group Order. */
static void fuzz_fetch_stream(int ver, wired_span in) {
  for (int desc = 0; desc < 2; desc++) {
    usz          off = 0;
    u64          rid;
    moqfetch_seq seq = {0};
    moqfetch_obj obj;
    seq.descending    = desc;
    seq.eor_timed_out = (moqver_caps(ver) & MOQVER_CAP_EOR_TIMED_OUT) != 0;
    if (moqfetch_hdr_take(in, &off, &rid) != MOQCTL_OK) return;
    while (moqfetch_obj_take(in, &off, &seq, &obj) == MOQCTL_OK) {
    }
  }
}

/* Reinterpret the same bytes as a data stream (SS11.4): classify, decode
 * the SUBGROUP_HEADER, then chain Object decodes until the bytes run out. */
static void fuzz_data_stream(int ver, wired_span in) {
  usz off  = 0;
  int kind = moqdata_classify(in, &off);
  if (kind == MOQDATA_STREAM_FETCH) fuzz_fetch_stream(ver, in);
  if (kind != MOQDATA_STREAM_SUBGROUP) return;

  moqdata_subhdr h;
  if (moqdata_subhdr_take(in, &off, &h) != MOQDATA_OK) return;
  moqdata_objseq seq = moqdata_objseq_of(h.type);
  moqdata_obj    obj;
  while (moqdata_obj_take(in, &off, &seq, &obj) == MOQDATA_OK) {
    moqdata_subhdr_resolve(&h, obj.object_id);
  }
}

/* And as a bare varint / KVP list (SS1.4.1 / SS10.2). */
static void fuzz_primitives(wired_span in) {
  usz off = 0;
  u64 v;
  moqvi_take(in, &off, &v);

  usz    koff      = 0;
  u64    prev_type = 0;
  moqkvp kv;
  while (moqkvp_take(in, &koff, &prev_type, &kv) == MOQKVP_OK) {
  }

  moqfetch_fill fill;
  moqfetch_fill_take(in, &fill); /* draft-22 FILL_PARAMETERS, 9.20.15 */
}

/* OBJECT_DATAGRAM (11.3.1): a datagram take accepts must re-encode, and
 * the re-encoding must decode to the same Object. */
static int fuzz_span_eq(wired_span a, wired_span b) {
  return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0);
}

static int fuzz_dg_eq(const moqdg_obj* a, const moqdg_obj* b) {
  return a->type == b->type && a->track_alias == b->track_alias &&
         a->group_id == b->group_id && a->object_id == b->object_id &&
         a->priority == b->priority && a->status == b->status &&
         fuzz_span_eq(a->props, b->props) &&
         fuzz_span_eq(a->payload, b->payload);
}

static void fuzz_dgram(wired_span in) {
  static u8 out[MOQDG_HDR_MAX + 9 + 65536];
  usz       off = 0, n = 0, off2 = 0;
  moqdg_obj a, b;
  if (in.n > sizeof out - MOQDG_HDR_MAX - 9) return;
  if (moqdg_take(in, &off, &a) != MOQDATA_OK) return;
  if (moqdg_put(wired_mspan_of(out, sizeof out), &n, &a) != MOQDATA_OK)
    __builtin_trap();
  if (moqdg_take(wired_span_of(out, n), &off2, &b) != MOQDATA_OK)
    __builtin_trap();
  if (!fuzz_dg_eq(&a, &b)) __builtin_trap();
}

/* The FETCH object cache (10.12.3) driven by 4-byte ops {tag|release,
 * group, object, payload len} into a small arena, then every track read
 * back the way a FETCH serves it: each item must advance the cursor. */
static void fuzz_cache_read(const moqcache* c, u64 tag) {
  moqctl_loc end = moqctl_loc_of(8, 0);
  moqctl_loc cur = moqcache_skip(c, tag, moqctl_loc_of(0, 0), end);
  for (int i = 0; i < 64 && moqctl_loc_less(cur, end); i++) {
    moqcache_item it;
    moqcache_item_at(c, tag, cur, end, &it);
    if (!moqctl_loc_less(cur, it.next)) __builtin_trap();
    cur = moqcache_skip(c, tag, it.next, end);
  }
}

static void fuzz_cache(wired_span in) {
  static u8 arena[512];
  moqcache  c;
  moqcache_init(&c, arena, sizeof arena);
  for (usz i = 0; i + 4 <= in.n; i += 4) {
    const u8* op  = in.p + i;
    usz       len = op[3] < in.n - i ? op[3] : in.n - i;
    if (op[0] & 0x80)
      moqcache_release(&c, op[0] & 1);
    else
      moqcache_append(
          &c, op[0] & 1, op[1] & 7, op[2] & 7, wired_span_of(in.p + i, len));
  }
  fuzz_cache_read(&c, 0);
  fuzz_cache_read(&c, 1);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;
  int        ver = data[0] % MOQVER_COUNT;
  wired_span in  = wired_span_of((const u8*)data + 1, (usz)size - 1);
  fuzz_ctl_stream(ver, in);
  fuzz_data_stream(ver, in);
  fuzz_primitives(in);
  fuzz_dgram(in);
  fuzz_cache(in);
  return 0;
}
