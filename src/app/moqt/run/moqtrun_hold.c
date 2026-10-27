#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_vi_cut(wired_span data);
static int moqtrun_pre_short(
    const wired_moqtrun_peer* p, wired_span data, int fin);

/* Dispatches data as control-stream bytes arriving on sid: the hub's
 * own (legacy bidi) stream reassembles in ctl_asm, a distinct client
 * control stream in peer_ctl_asm -- before acceptance both can carry
 * bytes in the same session, so they never share a reassembly. */
void moqtrun_ctl_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  p->rx_sid = sid;
  p->rx     = moqtrun_rx_is_own_ctl(p, sid) ? &p->ctl_asm : &p->peer_ctl_asm;
  moqtrun_dispatch_ctl_stream(hub, p, (usz)(p - hub->peers), data);
  p->rx = 0;
  if (fin) {
    moqtrun_ctl_gone(hub, p);
  }
}

/* draft-19 3.3: the first client control stream wins; a second one
 * closes the session. On adoption the delivery's remaining bytes
 * dispatch as control messages (the SETUP itself first). */
void moqtrun_ctl_adopt_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (p->peer_ctl_set) {
    moqtrun_second_ctl(hub, p);
    return;
  }
  p->peer_ctl_set       = 1;
  p->peer_ctl_stream_id = sid;
  moqtrun_ctl_rx(hub, p, sid, data, fin);
}

/* A SUBGROUP stream's head: its whole SUBGROUP_HEADER (draft-22 11.4.2),
 * 0 while data ends inside it; a malformed one is left to the stream's
 * normal path (its Type varint, at). */
static usz moqtrun_subgroup_head_len(wired_span data, usz at) {
  moqdata_subhdr h;
  usz            off = 0;
  int            r   = moqdata_subhdr_take(data, &off, &h);
  return r == MOQDATA_INSUFFICIENT ? 0 : (off ? off : at);
}

/* The bytes of data's stream head that must be whole before the stream is
 * classified: its first varint, or for a SUBGROUP stream the whole header
 * (its Track Alias picks the track). 0 while data ends inside it. */
usz moqtrun_head_len(wired_span data) {
  usz at = 0;
  if (moqdata_classify(data, &at) != MOQDATA_STREAM_SUBGROUP) {
    return at;
  }
  return moqtrun_subgroup_head_len(data, at);
}

/* 1 iff data is non-empty and ends inside its stream head. */
static int moqtrun_vi_cut(wired_span data) {
  return data.n != 0 && moqtrun_head_len(data) == 0;
}

static int moqtrun_pre_short(
    const wired_moqtrun_peer* p, wired_span data, int fin) {
  return p->pre_n == 0 && !fin && moqtrun_vi_cut(data);
}

/* RFC 9000 2.2: a fresh stream's first delivery may end inside its first
 * varint (SETUP's Type AF 00 cut after 0xAF). Classified as is, the
 * control stream is missed for good (ledger 12-12, TLC MoqtVerCtl F-A1),
 * so the bytes wait in p->pre until the varint is whole
 * (moqtrun_pre_feed). One pending stream per peer; a second, or one
 * ending in FIN, takes the unsplit path. 1 when kept. */
int moqtrun_pre_stash(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin) {
  if (!moqtrun_pre_short(p, data, fin)) {
    return 0;
  }
  bytes_memcpy(p->pre, data.p, data.n);
  p->pre_n   = (u8)data.n;
  p->pre_sid = sid;
  return 1;
}

/* draft-19 3.4/10.1: a fresh uni whose Stream Type is 0x2F00 is the
 * client's control stream. The Stream Type varint and the SETUP
 * message's own Type field are the SAME varint (compare FETCH_HEADER
 * 11.4.4, which is read the same way by moqfetch_hdr_take on the
 * unconsumed data) -- it is not repeated, so the classifying read must
 * not be consumed before the SETUP decode gets to see it. 1 when
 * consumed. */
int moqtrun_fresh_uni_ctl(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  usz at = 0;
  if (moqtrun_pre_stash(p, sid, data, fin)) {
    return 1;
  }
  if (moqdata_classify(data, &at) != MOQDATA_STREAM_CONTROL) {
    return 0;
  }
  moqtrun_ctl_adopt_rx(hub, p, sid, data, fin);
  return 1;
}

/* ============== pre-establishment hold (draft-19 3.3) ============== */

/* Streams are held while SETUP is incomplete: a token session until
 * both directions are done; a legacy session only until the hub's own
 * SETUP went out (its browser clients never send one back, and their
 * requests must flow regardless). */
int moqtrun_hold_gate(const wired_moqtrun_peer* p) {
  return p->legacy ? !p->ctl_opened : moqsess_should_buffer(&p->sess);
}

usz moqtrun_hold_rec_len(const wired_moqtrun_peer* p, usz at) {
  return (((usz)p->hold[at + 8] << 8) | p->hold[at + 9]) + MOQTRUN_HOLD_HDR;
}

/* An earlier delivery of sid is already held: later ones follow it into
 * the log whatever their bytes look like (mid-stream bytes must never
 * be re-classified). */
int moqtrun_hold_has(const wired_moqtrun_peer* p, u64 sid) {
  for (usz at = 0; at < p->hold_len; at += moqtrun_hold_rec_len(p, at)) {
    if (be_get_be64(p->hold + at) == sid) {
      return 1;
    }
  }
  return 0;
}

void moqtrun_hold_put(
    wired_moqtrun_peer* p, u64 sid, wired_span data, int fin) {
  u8* at = p->hold + p->hold_len;
  be_put_be64(at, sid);
  at[8]  = (u8)(data.n >> 8);
  at[9]  = (u8)data.n;
  at[10] = (u8)(fin != 0);
  bytes_memcpy(at + MOQTRUN_HOLD_HDR, data.p, data.n);
  p->hold_len += MOQTRUN_HOLD_HDR + data.n;
}
