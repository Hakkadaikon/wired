#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_encode_setup(wired_mspan buf, usz* off, const void* m);
static int moqtrun_encode_setup23(wired_mspan buf, usz* off, const void* m);
static moqtrun_body_encode_fn moqtrun_setup_encoder(int ver);
static usz                    moqtrun_len_room(int ver);
static usz                    moqtrun_len_put(u8* p, usz room, usz len);
static int                    moqtrun_env_body(
    wired_mspan buf, usz* end, moqtrun_body_encode_fn body_fn, const void* m);
static i64 moqtrun_ctl_open_io(
    wired_moqt_io* io, wired_wt_session* s, int legacy, wired_span b);

int wired_moqt_cache_attach(wired_moqt_hub* hub, u8* arena, usz size) {
  moqcache_init(&hub->cache, arena, size);
  return size != 0;
}

/* Length bytes reserved before the body: 16 bits, or (draft-23 9) the
 * 3 bytes a vi64 of any Length up to MOQCTL_MAX_MSG_LEN takes. */
static usz moqtrun_len_room(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_CTL_LEN_VI) ? 3 : 2;
}

/* Writes Length len into the room bytes at p, the body right after them:
 * 16 bits, or a minimal vi64 with the body moved down to meet it. The
 * Length's size. */
static usz moqtrun_len_put(u8* p, usz room, usz len) {
  usz k;
  if (room == 2) {
    be_put_be16(p, (u16)len);
    return 2;
  }
  k = moqvi_encode(p, len);
  bytes_move_down(p + k, p + room, len);
  return k;
}

/* The body after *end; 0 when it does not fit buf or is longer than
 * MOQCTL_MAX_MSG_LEN, which every peer's MAX_CONTROL_MESSAGE_SIZE admits
 * (draft-23 9.1.8: at least 65535) and the 16-bit Length can carry. */
static int moqtrun_env_body(
    wired_mspan buf, usz* end, moqtrun_body_encode_fn body_fn, const void* m) {
  usz at = *end;
  if (at > buf.n || !body_fn(buf, end, m)) {
    return 0;
  }
  return *end - at <= MOQCTL_MAX_MSG_LEN;
}

/* draft-23 9 / draft-18..22 SS10: Type + Length + Body in draft ver's
 * spelling; the envelope's size, 0 when it does not fit buf or the body
 * may not be sent (draft-23 9: never longer than the peer's
 * MAX_CONTROL_MESSAGE_SIZE). */
usz moqtrun_envelope_put(
    int                    ver,
    wired_mspan            buf,
    u64                    type,
    moqtrun_body_encode_fn body_fn,
    const void*            msg) {
  usz len_at = 0;
  if (!moqvi_put(buf, &len_at, type)) {
    return 0;
  }
  usz room = moqtrun_len_room(ver);
  usz end  = len_at + room;
  if (!moqtrun_env_body(buf, &end, body_fn, msg)) {
    return 0;
  }
  usz len = end - len_at - room;
  return len_at + moqtrun_len_put(buf.p + len_at, room, len) + len;
}

/* The hub's SETUP in a draft-23 session's option spelling (SSTS off 0x09;
 * no MAX_CONTROL_MESSAGE_SIZE: the hub's limit is the 65535 default). */
static int moqtrun_encode_setup23(wired_mspan buf, usz* off, const void* m) {
  return moqctl_setup_encode_v(MOQVER_D23, buf, off, m);
}

static int moqtrun_encode_setup(wired_mspan buf, usz* off, const void* m) {
  return moqctl_setup_encode(buf, off, m);
}

static moqtrun_body_encode_fn moqtrun_setup_encoder(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_OPT_MAX_CTL_SIZE)
             ? moqtrun_encode_setup23
             : moqtrun_encode_setup;
}

static i64 moqtrun_ctl_open_io(
    wired_moqt_io* io, wired_wt_session* s, int legacy, wired_span b) {
  return legacy ? io->open_bidi_stream(s, b) : io->open_uni_stream(s, b);
}

/* draft 3.3: the hub's control stream, its own SETUP as first bytes
 * (Setup Options: the hub's MAX_FILTER_RANGES / MAX_REQUEST_UPDATES
 * limits, 10.4). The draft-19 binding is a keep-open UNI stream whose
 * leading Stream Type varint (0x2F00, 3.4) IS the SETUP message's own
 * Type field -- the two are the same varint, not two (compare
 * FETCH_HEADER 11.4.4: one Type varint serves both the stream-type
 * table and the message layout); a legacy session keeps the pre-d17
 * single bidi the browser clients read, which carries no stream-type
 * varint at all. On a WT session the io open ops prefix the WebTransport
 * stream signal (draft-ietf-webtrans-http3-15 4.2); on raw QUIC the stream
 * starts with SETUP itself (-22 6.3) -- this layer stays session-opaque,
 * testable without the QUIC/TLS stack. A refused open leaves ctl_opened
 * 0: moqtrun_ctl_retry tries again on a later tick, and nothing (GOAWAY
 * included) is sent until SETUP went out. SETUP rides send_bufs[0], the
 * armed slot (an open holds the same view/ACK contract as stream_send,
 * srvrun.h). */
/* MAX_FILTER_RANGES (0x06) / MAX_REQUEST_UPDATES (0x08) exist from
 * draft-19 10.4 on; draft-18 10.3.1 has neither, so a draft-18 SETUP
 * leaves them 0 -- moqctl_setup_put_num keeps a 0 option off the wire. */
void moqtrun_setup_limits(moqctl_setup* s, int ver) {
  u64 caps = moqver_caps(ver);
  if (caps & MOQVER_CAP_RANGE_FILTERS) {
    s->max_filter_ranges = WIRED_MOQTRUN_MAX_FILTER_RANGES;
  }
  if (caps & MOQVER_CAP_MAX_REQUEST_UPDATES) {
    s->max_request_updates = WIRED_MOQTRUN_MAX_REQ_UPDATES;
  }
}

/* draft-19 10.3.1.5 (draft-18 10.3.1.5, draft-22 9.1.5): "An endpoint
 * SHOULD send a MOQT_IMPLEMENTATION option unless specifically configured
 * not to do so", the value only "the implementation name and version"
 * (13.8) -- the major version, nothing instance-identifying. */
static void moqtrun_setup_impl(const wired_moqt_hub* hub, moqctl_setup* s) {
  static const u8 name[] = "wired/0";
  s->has_implementation  = !hub->no_implementation;
  s->implementation      = wired_span_of(name, sizeof(name) - 1);
}

/* The control stream's urgency (MOQTRUN_CTL_URGENCY); an io table
 * without stream_priority leaves it at the transport default. */
void moqtrun_ctl_urgency(wired_moqt_io* io, wired_wt_session* s, u64 sid) {
  if (io->stream_priority) {
    io->stream_priority(s, sid, MOQTRUN_CTL_URGENCY);
  }
}

void moqtrun_ctl_open(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  wired_mspan buf = wired_mspan_of(p->send_bufs[0], WIRED_MOQTRUN_CTL_SEND_BUF);
  moqctl_setup setup = {0};
  moqtrun_setup_limits(&setup, p->ver);
  moqtrun_setup_impl(hub, &setup);
  moqtss_setup_opt(hub, p, &setup); /* SSTS (moqtssts_run.c) */
  usz off = moqtrun_envelope_put(
      p->ver, buf, MOQCTL_T_SETUP, moqtrun_setup_encoder(p->ver), &setup);
  i64 sid = moqtrun_ctl_open_io(
      &hub->io, p->wt, p->legacy, wired_span_of(buf.p, off));
  if (sid < 0) {
    return;
  }
  p->control_stream_id = (u64)sid;
  p->ctl_opened        = 1;
  moqtrun_ctl_urgency(&hub->io, p->wt, (u64)sid);
  moqsess_step(&p->sess, MOQSESS_EV_SENT_SETUP);
}

void moqtrun_peer_ctl_reset(wired_moqtrun_peer* p) {
  p->ctl_opened      = 0;
  p->request_id_next = 1; /* hub is the server: odd, 1-origin (SS10.2) */
  p->peer_rid_next   = 0; /* client Request IDs: even, 0-origin */
  p->peer_rid_base   = 0;
  p->peer_rid_seen   = 0;
  p->sub_names_n     = 0;
  p->sub_names_at    = 0;
  p->send_lens[0]    = 0;
  p->send_lens[1]    = 0;
  p->armed_idx       = 0;
  moqtrun_asm_reset(&p->ctl_asm);
  p->req               = 0;
  p->control_stream_id = 0;
}
