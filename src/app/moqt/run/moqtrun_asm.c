#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_asm_total(int ver, wired_span rest, usz* total);
static int moqtrun_asm_room(
    wired_moqt_hub* hub, wired_moqtrun_ctl_asm* a, usz total);
static void moqtrun_asm_skip(wired_moqtrun_ctl_asm* a, usz total);
static int  moqtrun_asm_fit(
    wired_moqt_hub* hub, int ver, wired_moqtrun_ctl_asm* a);
static void moqtrun_asm_fault(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, int r);
static void moqtrun_ctl_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx);

/* Once rest starts with a whole header (draft ver's Length spelling):
 * *total the whole message's size, MOQTRUN_ASM_OVER_CAP when its Length
 * is over MOQCTL_MAX_MSG_LEN, else MOQCTL_OK. While the header is
 * incomplete *total stays 0 (nothing to size yet). A vi64 Length is
 * clamped so *total cannot wrap (its message is skipped, never held). */
static int moqtrun_asm_total(int ver, wired_span rest, usz* total) {
  usz at = 0;
  u64 type;
  u64 len;
  if (moqctl_peek_header(ver, rest, &at, &type, &len) != MOQCTL_OK) {
    return MOQCTL_OK;
  }
  *total = at + (usz)u64_min(len, (u64)1 << 62);
  return len > MOQCTL_MAX_MSG_LEN ? MOQTRUN_ASM_OVER_CAP : MOQCTL_OK;
}

/* A message of total bytes fits a's buffer, or a leased pool one. */
static int moqtrun_asm_room(
    wired_moqt_hub* hub, wired_moqtrun_ctl_asm* a, usz total) {
  if (total <= moqtrun_asm_cap(a) || moqtrun_asm_lease(hub, a)) {
    return MOQCTL_OK;
  }
  return MOQTRUN_ASM_NO_POOL;
}

/* Consumes the total-byte message at a's head, now and across later
 * deliveries (a->skip). */
static void moqtrun_asm_skip(wired_moqtrun_ctl_asm* a, usz total) {
  usz held = (usz)u64_min(total, a->n - a->at);
  a->at += held;
  a->skip = total - held;
}

/* Makes room for the message at a's head: MOQCTL_OK (also while its
 * header is incomplete), or it is skipped whole and the reason returned
 * (MOQTRUN_ASM_OVER_CAP / MOQTRUN_ASM_NO_POOL). */
static int moqtrun_asm_fit(
    wired_moqt_hub* hub, int ver, wired_moqtrun_ctl_asm* a) {
  usz total = 0;
  int r     = moqtrun_asm_total(ver, moqtrun_asm_rest(a), &total);
  if (r == MOQCTL_OK) {
    r = moqtrun_asm_room(hub, a, total);
  }
  if (r != MOQCTL_OK) {
    moqtrun_asm_skip(a, total);
  }
  return r;
}

/* draft-23 9: a Length over the hub's MAX_CONTROL_MESSAGE_SIZE closes
 * FIELD_LENGTH_EXCEEDED (a 16-bit Length never is); a message no pool
 * buffer is left for closes INTERNAL_ERROR (the limit is ours). */
static void moqtrun_asm_fault(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, int r) {
  moqtrun_close_with(
      hub, p,
      r == MOQTRUN_ASM_OVER_CAP ? WIRED_MOQTRUN_CLOSE_FIELD_LENGTH_EXCEEDED
                                : WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR);
}

/* Discards the bytes of a skipped message still owed (a->skip), then
 * appends as much of *data as fits a's buffer and advances *data past
 * everything consumed. */
void moqtrun_asm_push(wired_moqtrun_ctl_asm* a, wired_span* data) {
  usz drop = (usz)u64_min(a->skip, data->n);
  a->skip -= drop;
  moqtrun_span_drop(data, drop);
  moqtrun_asm_unlease(a);
  moqtrun_asm_compact(a, moqtrun_asm_mem(a));
  usz take = (usz)u64_min(moqtrun_asm_cap(a) - a->n, data->n);
  bytes_memcpy(moqtrun_asm_mem(a) + a->n, data->p, take);
  a->n += take;
  moqtrun_span_drop(data, take);
}

/* 1 when the push took bytes from *data (loop: push, drain, repeat). */
int moqtrun_asm_feed(wired_moqtrun_ctl_asm* a, wired_span* data) {
  usz before = data->n;
  moqtrun_asm_push(a, data);
  return data->n < before;
}

/* a's unread bytes. */
wired_span moqtrun_asm_rest(const wired_moqtrun_ctl_asm* a) {
  const u8* m = a->big ? a->big : a->buf;
  return wired_span_of(m + a->at, a->n - a->at);
}

/* Next complete message held in a, read as p's draft spells the envelope
 * (moqctl_peek_type_v's result, *body a view valid until the next push or
 * pop), or MOQCTL_INSUFFICIENT when more bytes are needed. A message
 * longer than the inline buffer is reassembled in a leased pool buffer;
 * one over MOQCTL_MAX_MSG_LEN, or finding the pool exhausted, is skipped
 * by its Length and closes p's session (moqtrun_asm_fault). */
int moqtrun_asm_pop(
    wired_moqt_hub*        hub,
    wired_moqtrun_peer*    p,
    wired_moqtrun_ctl_asm* a,
    u64*                   type,
    wired_span*            body) {
  moqtrun_asm_unlease(a);
  if (a->skip) {
    return MOQCTL_INSUFFICIENT; /* rest of a held message */
  }
  int r = moqtrun_asm_fit(hub, p->ver, a);
  if (r != MOQCTL_OK) {
    moqtrun_asm_fault(hub, p, r);
    return MOQCTL_INSUFFICIENT;
  }
  usz off = 0;
  r       = moqctl_peek_type_v(p->ver, moqtrun_asm_rest(a), &off, type, body);
  a->at += off;
  return r;
}

/* Routes every complete message the handled stream's reassembly holds. */
static void moqtrun_ctl_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  u64        type = 0;
  wired_span body = {0, 0};
  int        r;
  while ((r = moqtrun_asm_pop(hub, p, moqtrun_cur_asm(p), &type, &body)) !=
         MOQCTL_INSUFFICIENT) {
    moqtrun_msg_route(p, r, type, body)(hub, p, peer_idx, body);
  }
}

/* Dispatches every complete control message found in data on the stream
 * p is handling (p->req, else the control stream), prefixed by the
 * incomplete tail the previous call left in that stream's reassembly -- a
 * message may arrive split across calls. peer_idx is
 * passed through for handlers that need to record which session a subscription
 * belongs to. Every handler queues its reply (moqtrun_queue_reply) rather than
 * sending it immediately.
 *
 * Flushes at BOTH ends: the leading flush retries whatever an earlier
 * dispatch could not send yet (moqtrun_flush_replies' own doc -- a
 * keep-open bidi stream's previous round must be acknowledged before a new
 * one is accepted, and that can still be pending when the next dispatch
 * starts), and the trailing flush sends this dispatch's own new replies.
 * Two calls, never more, keeps every reply either delivered or still
 * queued for the next try -- never dropped. */
void moqtrun_dispatch_ctl_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span data) {
  moqtrun_flush_cur(&hub->io, p);
  do {
    moqtrun_asm_push(moqtrun_cur_asm(p), &data);
    moqtrun_ctl_drain(hub, p, peer_idx);
  } while (data.n > 0);
  moqtrun_flush_cur(&hub->io, p);
}

usz wired_moqt_publish_blob(
    wired_moqt_hub* hub,
    wired_span      name,
    u64             track_alias,
    wired_span      blob,
    wired_mspan     wire) {
  if (moqtrun_key_oversized(moqtrun_key_name(name))) {
    return 0;
  }
  usz n = moqdata_blob_build(wire, track_alias, blob);
  if (n == 0) {
    return 0;
  }
  moqtrun_track_claim(
      hub, &hub->blob_track, moqtrun_key_name(name), track_alias);
  hub->blob_wire = wired_span_of(wire.p, n);
  moqdata_objseq seq;
  u64            group;
  moqtrun_subgroup_scan(hub->blob_wire, &hub->blob_track, &seq, &group);
  return n;
}
