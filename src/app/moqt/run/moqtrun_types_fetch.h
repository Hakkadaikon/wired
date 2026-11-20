#ifndef APP_MOQT_RUN_MOQTRUN_TYPES_FETCH_H
#define APP_MOQT_RUN_MOQTRUN_TYPES_FETCH_H

/* The FETCH-serving slot type of moqtrun_types.h, in its own header to
 * keep that file at the Halstead volume gate; included from there only. */

/** One FETCH response being served from the hub cache: Objects of the
 * track incarnation cache_tag in [cursor, end) go out on one uni stream
 * (FETCH_HEADER, then fetch Objects, 11.4.4), one item per stream round
 * as the transport accepts them. The cursor is a Location, never a
 * pointer into the cache: an item is looked up again on every round, so
 * eviction or a publisher leaving in between turns it into an End of
 * Unknown Range instead of reading freed bytes. */
typedef struct {
  /** The requesting session (owned by the transport). */
  wired_wt_session* wt;
  /** The FETCH's Request ID (a fill: its subscription's). */
  u64 request_id;
  /** The track incarnation served (wired_moqtrun_track.cache_tag). */
  u64 cache_tag;
  /** Next Location to serve. */
  moqctl_loc cursor;
  /** First Location past the range. */
  moqctl_loc end;
  /** The hub-opened uni stream the response goes out on. */
  u64 stream_id;
  /** Fetch-Object encoding state carried between items (11.4.4). */
  moqfetch_seq seq;
  /** Fill only: the owning subscription's Request ID -- with wt it is the
   * owner key. A fill outlives its subscription's PUBLISH_DONE until its
   * own FIN, so no pointer or index into a reusable subscription slot is
   * ever held. */
  u64 owner_rid;
  /** Descending only: the first Location of the whole range. */
  moqctl_loc lo;
  /** Clock (wired_moqt_tick) of the last accepted round: a fetch refused
   * for longer than WIRED_MOQTREL_STALL_MS is given up. */
  u64 last_ok_ms;
  /** The upstream session the FETCH went to. */
  wired_wt_session* up_wt;
  /** The hub-opened request stream carrying the upstream FETCH. */
  u64 up_req_sid;
  /** The upstream FETCH's Request ID (its FETCH_HEADER names it). */
  u64 up_rid;
  /** The upstream fetch data stream. */
  u64 up_data_sid;
  /** Fetch-Object decoding state of the upstream data stream. */
  moqfetch_seq up_seq;
  /** Upstream Locations must lie in [up_lo, up_span_end): the range start
   * and, ascending, the first Location the cache vouches for again
   * (descending: the range end). */
  moqctl_loc up_lo;
  /** See up_lo. */
  moqctl_loc up_span_end;
  /** The last relayed item's Location; valid iff has_up_last. */
  moqctl_loc up_last;
  /** Payload bytes of the Object at up_last still to pass through as
   * they arrive (its head and the bytes before went out already). */
  u64 up_pl_left;
  /** Payload bytes of that Object passed through so far. */
  u64 up_pl_at;
  /** The upstream FETCH_OK End Location, inclusive; valid iff
   * up_state is WIRED_MOQTRUN_UPF_OK. */
  moqctl_loc up_end;
  /** Clock past which the upstream FETCH is cancelled. */
  u64 up_deadline_ms;
  /** The leg's budget: min(FILL_TIMEOUT, WIRED_MOQTRUN_UPFETCH_BUDGET_MS). */
  u64 up_budget_ms;
  /** no_track: the downstream request stream the answer goes on. */
  u64 req_sid;
  /** 1 while the slot serves (or, in fetch_waits, holds) a fetch. */
  int in_use;
  /** 1 once the stream is open (stream_id valid). */
  int opened;
  /** 1 when this fetch is a fill of a subscription (draft-22 SS9.20.15):
   * it was opened by the hub, not requested by a FETCH. */
  int is_fill;
  /** Fill only: 1 once the upstream publisher left. An open fill was
   * reset at once; a held one opens later only to reset (failure is
   * signalled by open-then-reset, draft-22 3.3.4). */
  int failed;
  /** 1 when Group Order is Descending (11.4.4.1): [cursor, end) is then
   * one group's window, stepped down a group at a time until lo's. */
  int descending;
  /** WIRED_MOQTRUN_UPF_*: the upstream FETCH filling the front of the
   * range. While it is in flight the cache side neither serves nor
   * stall-checks; [cursor, end) waits untouched for it to end. */
  int up_state;
  /** 1 once the upstream data stream up_data_sid is bound to this slot;
   * it stays bound (later bytes are discarded) after the leg ends. */
  int up_data_open;
  /** 1 once the upstream data stream ended (FIN or reset). */
  int up_data_end;
  /** 1 once an upstream item was relayed. */
  int has_up_last;
  /** The upstream FETCH_OK End Of Track. */
  int up_eot;
  /** 1 when the cache side reports what it lacks as timed out: the
   * budget ran out, or FILL_TIMEOUT was 0. */
  int up_tmo;
  /** 1 for a FETCH of a track the hub does not hold: its FETCH_OK waits
   * for the upstream one. */
  int no_track;
  /** no_track: 1 once the downstream FETCH was answered. */
  int answered;
  /** 1 while the upstream Object under way failed the Range Filters: its
   * payload is read past, never relayed (moqtrun_upf_chunk). */
  int up_skip;
  /** The FETCH's Range Filter rows (a fill: its subscription's), applied
   * to every Object served, cached or upstream (draft-22 3.3.3). */
  wired_moqtrun_rngrow rngf[WIRED_MOQTRUN_MAX_FILTER_RANGES];
  /** Rows of rngf in use; 0 = unfiltered. */
  u8 rngf_n;
} wired_moqtrun_fetch;

#endif
