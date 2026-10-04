/* Hub fill fetch streams (draft-22 SS9.20.15 FILL_PARAMETERS): a
 * subscription's cached backlog served on a fetch data stream beside the
 * live subscription. Reuses the recording io stubs (moqtrun_test.c), the
 * subscription fixtures (moqtrun_sub_test.c) and the fetch-stream readers
 * (moqtrun_fetch_test.c) of the same unity TU. */

/* B SUBSCRIBEs to alice on draft-22 with FILL_PARAMETERS fill attached
 * (params list: the fill value, plus any extra in base); returns the
 * SUBSCRIBE's Request ID. */
static u8  mfill_val[64];
static u64 mfill_rid = 600;

static moqctl_params mfill_params(
    const moqfetch_fill* fill, const moqctl_params* base) {
  moqctl_params p = base ? *base : (moqctl_params){0};
  usz           n = 0;
  CHECK(
      moqfetch_fill_put(wired_mspan_of(mfill_val, sizeof mfill_val), &n, fill));
  p.items[p.n].type  = MOQCTL_PARAM_FILL_PARAMETERS;
  p.items[p.n].enc   = MOQCTL_PENC_BYTES;
  p.items[p.n].bytes = wired_span_of(mfill_val, n);
  p.n++;
  return p;
}

static u64 mfill_subscribe(
    const moqfetch_fill* fill, const moqctl_params* base) {
  moqctl_ftn    f                            = mf_track();
  moqctl_params p                            = mfill_params(fill, base);
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D22;
  mfill_rid += 2;
  mtst_subscribe_p(SESS_B, mf_ctrl_b, &f, mfill_rid, &p);
  return mfill_rid;
}

/* An open-ended fill on a fresh FORWARD-1 subscription: one uni stream,
 * FETCH_HEADER carrying the SUBSCRIBE's Request ID, the cached range in
 * ascending order, FIN at the end (SS9.20.15). */
static void test_moqtrun_fill_subscribe_opens(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  u64 rid = mfill_subscribe(&fill, 0);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 1, 0, 1));
  CHECK(mf_fin);
}

/* Fetch streams opened toward B (FETCH_HEADER type byte). */
static usz mfill_opens(void) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) n += mf_opens(&g_calls[i]) != 0;
  return n;
}

/* An explicit fill end past the Largest Object is cut to it: nothing
 * past Largest is sent and nothing is waited for (SS9.20.15). */
static void test_moqtrun_fill_end_clipped_to_largest(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  fill.has_filter      = 1;
  fill.range.sk        = MOQCTL_RSK_ABS;
  fill.range.ek        = MOQCTL_REK_GROUP;
  fill.range.end_group = 1; /* past Largest {0,1} */
  mfill_subscribe(&fill, 0);
  CHECK(mf_read());
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_fin);
}

/* A fill starting past the Largest Object, or on a track with nothing
 * published, opens no stream; the subscription itself establishes. */
static void test_moqtrun_fill_empty_or_future_range(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  fill.has_filter        = 1;
  fill.range.sk          = MOQCTL_RSK_ABS;
  fill.range.start_group = 5;
  fill.range.ek          = MOQCTL_REK_UNBOUNDED;
  mfill_subscribe(&fill, 0);
  CHECK(mfill_opens() == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  mf_init(sizeof mf_arena); /* nothing published at all */
  moqfetch_fill none = {0};
  mfill_subscribe(&none, 0);
  CHECK(mfill_opens() == 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
}

/* An open-ended filtered fill ends at the Largest Object current when
 * it is processed (SS9.20.9: an omitted end is Largest). */
static void test_moqtrun_fill_open_end_is_largest(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  fill.has_filter = 1;
  fill.range.sk   = MOQCTL_RSK_ABS;
  fill.range.ek   = MOQCTL_REK_UNBOUNDED;
  mfill_subscribe(&fill, 0);
  CHECK(mf_read());
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 1, 0, 1));
  CHECK(mf_fin);
}

/* B SUBSCRIBEs to alice on request stream MTRQ_S1 (draft-22) with params
 * (0 = none); returns the SUBSCRIBE's Request ID. */
static u64 mfill_subscribe_req(const moqctl_params* params) {
  moqctl_ftn f                               = mf_track();
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = MOQVER_D22;
  mfill_rid += 2;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mfill_rid, params);
  return mfill_rid;
}

/* REQUEST_UPDATE carrying FILL_PARAMETERS on MTRQ_S1; returns its own
 * fresh Request ID (mtst_rid). */
static u64 mfill_update(const moqfetch_fill* fill, const moqctl_params* base) {
  moqctl_params p = mfill_params(fill, base);
  mtup_update(SESS_B, MTRQ_S1, &p);
  return mtst_rid;
}

/* A REQUEST_UPDATE without FILL_PARAMETERS opens no fill; one carrying
 * it opens a fill whose FETCH_HEADER has the REQUEST_UPDATE's Request ID,
 * and an earlier fill keeps running beside it (draft-22 9.8, 9.20.15). */
static void test_moqtrun_fill_update_opens(void) {
  moqfetch_fill fill  = {0};
  moqctl_params plain = mtst_params_u8(MOQCTL_PARAM_SUBSCRIBER_PRIORITY, 7);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_subscribe_req(0);
  mtup_update(SESS_B, MTRQ_S1, &plain);
  CHECK(mfill_opens() == 0);
  u64 rid = mfill_update(&fill, 0);
  CHECK(mfill_opens() == 1);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 1 && mf_is_obj(0, 0, 0, 1));
  CHECK(mf_fin);
}

/* FORWARD gates every fill request: FILL_PARAMETERS on a FORWARD-0
 * SUBSCRIBE opens nothing, a plain FORWARD-1 resume does not revive it,
 * an update going 1 -> 0 with FILL_PARAMETERS opens nothing, and only
 * 0 -> 1 together with FILL_PARAMETERS opens the fill. */
static void test_moqtrun_fill_forward_gates(void) {
  moqfetch_fill fill = {0};
  moqctl_params p0   = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_params p1   = mtst_params_u8(MOQCTL_PARAM_FORWARD, 1);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  moqctl_params sub = mfill_params(&fill, &p0);
  mfill_subscribe_req(&sub);
  CHECK(mfill_opens() == 0);
  mtup_update(SESS_B, MTRQ_S1, &p1); /* plain resume */
  CHECK(mfill_opens() == 0);
  mfill_update(&fill, &p0); /* 1 -> 0 with a fill */
  CHECK(mfill_opens() == 0);
  u64 rid = mfill_update(&fill, &p1); /* 0 -> 1 with a fill */
  CHECK(mfill_opens() == 1);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
}

/* Two fills run at once: a SUBSCRIBE fill still draining and an update
 * fill opened beside it, each under its own Request ID; both drain to
 * FIN with no reset. */
static void test_moqtrun_fill_two_at_once(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  g_stream_send_ok_n = 0; /* streams open, rounds refused */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(mfill_opens() == 1);
  mfill_update(&fill, 0);
  CHECK(mfill_opens() == 2);
  CHECK(!mf_no_fetch());
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mf_no_fetch());
  CHECK(moqtrun_test_count_kind(7) == 0);
}

/* C's Object {g, o} of n bytes on a fresh one-shot stream (the
 * re-publishing session's twin of mf_obj). */
static void mfill_obj_c(u64 g, u64 o, usz n) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u8             pl[MOQTRUN_TEST_MAX_PAYLOAD];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x30;
  h.track_alias      = MF_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  for (usz i = 0; i < n; i++) pl[i] = (u8)(16 * g + o);
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, o, wired_span_of(pl, n));
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_C, 3002, wired_span_of(buf, off), 1);
}

/* A subscription revived by a new PUBLISH (no SUBSCRIBE round) is
 * filled only through REQUEST_UPDATE; the FETCH_HEADER carries that
 * update's Request ID. */
static void test_moqtrun_fill_publish_started_sub(void) {
  moqfetch_fill fill = {0};
  moqctl_ftn    f    = mf_track();
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_subscribe_req(0);
  mtst_publish(SESS_C, mtst_join(SESS_C), &f, MF_ALIAS); /* supersedes A */
  moqtrun_test_reset();
  mfill_obj_c(0, 0, 2);
  CHECK(mtst_sub(SESS_C, SESS_B) != 0); /* re-attached by the PUBLISH */
  usz before = mfill_opens();
  u64 rid    = mfill_update(&fill, 0);
  CHECK(mfill_opens() == before + 1);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 1 && mf_is_obj(0, 0, 0, 2));
  CHECK(mf_fin);
}

/* Reads B's last fetch stream as a fill stream (fills exist on draft-22
 * only, so 0x20C End of Timed-Out Range is legal on it, SS11.4.1). */
static int mfill_read(void) {
  moqfetch_seq seq  = {0};
  seq.eor_timed_out = 1;
  return mf_read_seq(seq);
}

/* mfill_read of a Group Order Descending stream (Group ID Deltas run the
 * other way, 11.4.4.1). */
static int mfill_read_desc(void) {
  moqfetch_seq seq  = {0};
  seq.eor_timed_out = 1;
  seq.descending    = 1;
  return mf_read_seq(seq);
}

/* Item i is an End of Timed-Out Range ending at {g, o}. */
static int mfill_is_tmo(usz i, u64 g, u64 o) {
  return i < mf_n && mf_items[i].flags == MOQFETCH_EOR_TIMED_OUT &&
         mf_items[i].group == g && mf_items[i].object == o;
}

/* A Location the cache cannot serve is reported at once as End of
 * Timed-Out Range (0x20C): the hub keeps no upstream FETCH, so it never
 * waits, whatever FILL_TIMEOUT says (SS9.20.15). */
static void test_moqtrun_fill_miss_is_timed_out_now(void) {
  moqfetch_fill fill = {0};
  fill.has_timeout   = 1;
  fill.timeout_ms    = 5000;
  mf_init(0); /* no cache: the whole range is a miss */
  mf_obj(0, 0, 1);
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read());
  CHECK(mf_n == 1 && mfill_is_tmo(0, 0, 0));
  CHECK(mf_fin);
  mf_init(0);
  mf_obj(0, 0, 1);
  fill.timeout_ms = 0;
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read());
  CHECK(mf_n == 1 && mfill_is_tmo(0, 0, 0));
  CHECK(mf_fin);
}

/* A run of evicted Locations is one 0x20C naming the run's end, the
 * remaining Objects follow and the fill still FINs only after the whole
 * range (SS11.4.1, SS9.20.15). */
static void test_moqtrun_fill_evicted_run_collapsed(void) {
  moqfetch_fill fill = {0};
  mf_init(2 * (MOQCACHE_HDR + 1));
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1); /* evicts group 0 */
  mf_obj(1, 1, 1);
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read());
  CHECK(mf_n == 3);
  CHECK(mfill_is_tmo(0, 0, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_is_obj(1, 1, 0, 1) && mf_is_obj(2, 1, 1, 1));
  CHECK(mf_fin);
}

/* An eviction while the fill is underway (cursor parked on a refused
 * round) turns the pending Location into 0x20C, never stale bytes, and
 * the fill continues to FIN. */
static void test_moqtrun_fill_eviction_under_cursor(void) {
  moqfetch_fill fill = {0};
  mf_init(4 * (MOQCACHE_HDR + 1));
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_obj(1, 1, 1);
  g_stream_send_ok_n = 1;
  mfill_subscribe(&fill, 0);
  mf_obj(2, 0, 1); /* evicts group 0 */
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mfill_read());
  CHECK(mf_is_obj(0, 0, 0, 1));
  CHECK(mfill_is_tmo(1, 0, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_fin);
}

/* A Group Order Descending fill sends groups from the range's end to its
 * start, Objects within a group still ascending, and FINs only after the
 * whole range (SS9.20.15, 11.4.4.1). */
static void test_moqtrun_fill_descending(void) {
  moqfetch_fill fill = {0};
  fill.descending    = 1;
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read_desc());
  CHECK(mf_n == 3);
  CHECK(mf_is_obj(0, 1, 0, 1));
  CHECK(mf_is_obj(1, 0, 0, 1) && mf_is_obj(2, 0, 1, 1));
  CHECK(mf_fin);
}

/* A descending fill walks past a Group that never existed without
 * emitting anything for it, and the real last Object carries FIN. */
static void test_moqtrun_fill_descending_skips_gap(void) {
  moqfetch_fill fill = {0};
  fill.descending    = 1;
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(2, 0, 1); /* group 1 never published */
  mfill_subscribe(&fill, 0);
  CHECK(mfill_read_desc());
  CHECK(mf_n == 2);
  CHECK(mf_is_obj(0, 2, 0, 1) && mf_is_obj(1, 0, 0, 1));
  CHECK(mf_fin);
}

/* One-shot subgroup relay rounds toward B (SUBGROUP_HEADER mode 0x30,
 * the only header the publisher fixtures write). */
static usz mfill_live_count(void) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++)
    n += g_calls[i].s == SESS_B && g_calls[i].kind == 4 &&
         g_calls[i].payload_len && g_calls[i].payload[0] == 0x30;
  return n;
}

/* A Next Object subscription with an open-ended fill: the fill carries
 * everything up to the Largest Object at SUBSCRIBE time and FINs, the
 * live subscription starts right after it -- each Location exactly once
 * (SS9.20.15 with SS9.20.9's Next Object). */
static void test_moqtrun_fill_next_object_no_gap(void) {
  moqfetch_fill fill = {0};
  moqctl_params lo   = mtst_params_filter(MOQCTL_FILTER_LARGEST);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mfill_subscribe(&fill, &lo);
  CHECK(mfill_read());
  CHECK(mf_n == 2 && mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_fin);
  CHECK(mfill_live_count() == 0); /* nothing replayed onto the live side */
  mf_obj(0, 2, 1);
  CHECK(mf_relayed(0, 2));
  CHECK(mfill_live_count() == 1);
}

/* A REQUEST_UPDATE fill overlapping Locations the live subscription
 * already delivered duplicates them only inside the overlap: the fill
 * serves its whole range, the live side sent each Object once. */
static void test_moqtrun_fill_update_overlap_dup(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_subscribe_req(0);
  mf_obj(0, 1, 1); /* delivered live to B */
  CHECK(mf_relayed(0, 1));
  u64 rid = mfill_update(&fill, 0);
  CHECK(mfill_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 2 && mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_fin);
  CHECK(mfill_live_count() == 1); /* (0,1) went live once, (0,0) never */
}

/* The i-th fetch stream id opened toward B (open order). */
static u64 mfill_sid(usz which) {
  usz seen = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (mf_opens(&g_calls[i]) && seen++ == which) return g_calls[i].stream_id;
  return ~(u64)0;
}

/* STOP_SENDING on a fill stream ends that fill alone: its slot frees,
 * the subscription stays Established and keeps delivering (draft-22
 * 3.3.4 scopes the cancel to the one data stream). */
static void test_moqtrun_fill_stop_sending_leaves_sub(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0; /* the fill parks mid-range */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(!mf_no_fetch());
  g_stream_send_ok_n = -1;
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mfill_sid(0), 0, 0);
  CHECK(mf_no_fetch());
  mf_obj(0, 1, 1); /* still relayed live */
  CHECK(mf_relayed(0, 1));
}

/* Cancelling the subscription (its request stream reset, 3.3.3) resets
 * every fill it owns -- the SUBSCRIBE's and a REQUEST_UPDATE's alike --
 * and frees their slots. */
static void test_moqtrun_fill_cancel_resets_all(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0; /* both fills park mid-range */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  mfill_update(&fill, 0);
  CHECK(mfill_opens() == 2);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  CHECK(mf_reset_sent(mfill_sid(0)) && mf_reset_sent(mfill_sid(1)));
  CHECK(mf_no_fetch());
}

/* The reset code the hub sent on stream sid (rides the recorder's fin
 * field), or -1 when sid was never reset. */
static int mfill_reset_code(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 7 && g_calls[i].stream_id == sid)
      return g_calls[i].fin;
  return -1;
}

/* A subscriber that stops reading an OPEN fill past the stall limit gets
 * it reset with DELIVERY_TIMEOUT -- the draft names this situation and
 * this code -- while the subscription itself stays Established. */
static void test_moqtrun_fill_stall_delivery_timeout(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0; /* opened, rounds never accepted */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(!mf_no_fetch());
  wired_moqt_tick(&mtst_hub, WIRED_MOQTREL_STALL_MS + 1);
  CHECK(mfill_reset_code(mfill_sid(0)) == MOQTRUN_RESET_DELIVERY_TIMEOUT);
  CHECK(mf_no_fetch());
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
}

/* A fill the transport will not grant a uni stream for is held unopened
 * -- silently, past any stall limit, with no reset and no REQUEST_ERROR
 * -- and opens the moment credit arrives, joining the normal path. */
static void test_moqtrun_fill_blocked_open_held(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_open_uni_fail_n = 100; /* no uni-stream credit for a while */
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(!mf_no_fetch()); /* held, not dropped */
  wired_moqt_tick(&mtst_hub, WIRED_MOQTREL_STALL_MS + 1);
  CHECK(!mf_no_fetch());                  /* still held: no give-up */
  CHECK(moqtrun_test_count_kind(7) == 0); /* and no reset sent */
  g_open_uni_fail_n = 0;                  /* credit arrives */
  wired_moqt_tick(&mtst_hub, WIRED_MOQTREL_STALL_MS + 2);
  CHECK(mfill_read());
  CHECK(mf_n == 1 && mf_is_obj(0, 0, 0, 1));
  CHECK(mf_fin);
  CHECK(mf_no_fetch());
}

/* The upstream publisher leaving mid-fill resets every open fill of its
 * track with INTERNAL_ERROR: a fill is a live continuation of its
 * subscription, not a cacheable FETCH, so it cannot go on. */
static void test_moqtrun_fill_upstream_gone_resets(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0; /* the fill parks mid-range, opened */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(!mf_no_fetch());
  g_stream_send_ok_n = -1;
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mfill_reset_code(mfill_sid(0)) == MOQTRUN_RESET_INTERNAL_ERROR);
  CHECK(mf_no_fetch());
}

/* A held (unopened) fill whose upstream left cannot signal yet: it stays
 * silent until the transport grants the stream, then opens it only to
 * reset INTERNAL_ERROR -- failure is signalled by open-then-reset. */
static void test_moqtrun_fill_blocked_upstream_gone(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_open_uni_fail_n = 100;
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  CHECK(!mf_no_fetch());
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(!mf_no_fetch()); /* held: no stream, so no reset yet */
  CHECK(moqtrun_test_count_kind(7) == 0);
  g_open_uni_fail_n = 0;
  wired_moqt_tick(&mtst_hub, 1);
  u64 sid = mf_data_sid(); /* opened only to signal the failure */
  CHECK(mfill_reset_code(sid) == MOQTRUN_RESET_INTERNAL_ERROR);
  for (usz i = 0; i < g_n_calls; i++) /* header only, no Objects */
    CHECK(!(g_calls[i].kind == 3 && g_calls[i].stream_id == sid));
  CHECK(mf_no_fetch());
}

/* Stream Count of the last PUBLISH_DONE sent on sid; ~0 when none was
 * sent (a round may carry several messages). */
static u64 mfill_done_count(u64 sid) {
  for (usz i = g_n_calls; i > 0; i--) {
    const moqtrun_test_call* c   = &g_calls[i - 1];
    usz                      off = 0, boff = 0;
    u64                      type;
    wired_span               body;
    moqctl_publish_done      d;
    if ((c->kind != 3 && c->kind != 12) || c->stream_id != sid) continue;
    while (moqctl_peek_type(
               wired_span_of(c->payload, c->payload_len), &off, &type, &body) ==
           MOQCTL_OK)
      if (type == MOQCTL_T_PUBLISH_DONE &&
          moqctl_publish_done_take(body, &boff, &d) == MOQCTL_OK)
        return d.stream_count;
  }
  return ~(u64)0;
}

/* PUBLISH_DONE's Stream Count covers the subscription's relay streams
 * AND its fill streams on the same counter (draft 10.10, 9.20.15). */
static void test_moqtrun_fill_counts_in_done(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub); /* one fill stream, served to FIN */
  mf_obj(1, 0, 1);           /* one live relay stream */
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mfill_done_count(MTRQ_S1) == 2);
}

/* PUBLISH_DONE waits while a fill is still held unopened: a stream may
 * never open after it. It goes out -- held fills included in its Stream
 * Count -- once the transport grants the stream. */
static void test_moqtrun_fill_done_waits_for_held(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  g_open_uni_fail_n = 100;
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub); /* the fill is held unopened */
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mfill_done_count(MTRQ_S1) == ~(u64)0); /* deferred */
  CHECK(mtrq_fin_on(MTRQ_S1) == 0);
  g_open_uni_fail_n = 0;
  wired_moqt_tick(&mtst_hub, 1); /* opens (and resets: upstream gone) */
  wired_moqt_tick(&mtst_hub, 2); /* flushes the owed PUBLISH_DONE */
  CHECK(mfill_done_count(MTRQ_S1) == 1);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
}

/* Fills every fetch-serving slot with a parked plain FETCH (opened, its
 * one round refused); their stream ids come back through mfill_sid. */
static void mfill_occupy_slots(void) {
  g_stream_send_ok_n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    mf_standalone(mf_loc(0, 0), mf_loc(0, 1));
}

/* A fill accepted while every fetch-serving slot is busy is held -- no
 * stream, no reset, no REQUEST_ERROR -- and opens the moment a slot
 * frees, joining the normal serve-to-FIN path (SS9.20.15). */
static void test_moqtrun_fill_slot_full_held(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_occupy_slots();
  moqctl_params sub = mfill_params(&fill, 0);
  u64           rid = mfill_subscribe_req(&sub);
  CHECK(mfill_opens() == WIRED_MOQTRUN_MAX_FETCHES); /* held: no 9th open */
  CHECK(moqtrun_test_count_kind(7) == 0);            /* and no reset */
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mfill_sid(0), 0, 0);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mf_read());
  CHECK(mf_hdr_rid == rid);
  CHECK(mf_n == 1 && mf_is_obj(0, 0, 0, 1));
  CHECK(mf_fin);
}

/* Cancelling the subscription while its fill waits for a slot drops the
 * fill without ever opening a stream (3.3.3). */
static void test_moqtrun_fill_slot_full_cancel_drops(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_occupy_slots();
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0); /* cancel */
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mfill_sid(0), 0, 0);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mfill_opens() == WIRED_MOQTRUN_MAX_FETCHES); /* never opened */
}

/* PUBLISH_DONE waits for a slot-starved fill exactly like for one the
 * transport refused: the upstream leaving meanwhile makes the fill open
 * -- once a slot frees -- only to reset INTERNAL_ERROR, and the owed
 * PUBLISH_DONE then goes out counting it. */
static void test_moqtrun_fill_slot_full_done_waits(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mfill_occupy_slots();
  moqctl_params sub = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  wired_moqt_on_session_close(&mtst_hub, SESS_A); /* upstream gone */
  CHECK(mfill_done_count(MTRQ_S1) == ~(u64)0);    /* deferred */
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    wired_moqt_on_stream_reset(&mtst_hub, SESS_B, mfill_sid(i), 0, 0);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 1); /* opens only to signal the failure */
  CHECK(mfill_reset_code(mf_data_sid()) == MOQTRUN_RESET_INTERNAL_ERROR);
  wired_moqt_tick(&mtst_hub, 2);
  CHECK(mfill_done_count(MTRQ_S1) == 1);
}

/* The index of the first accepted data round on sid, or ~0. */
static usz mfill_send_idx(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 3 && g_calls[i].stream_id == sid &&
        !g_calls[i].refused)
      return i;
  return ~(usz)0;
}

/* B's long-lived relay stream (SUBGROUP_HEADER opening round). */
static u64 mfill_relay_sid(void) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].s == SESS_B && g_calls[i].kind == 5 &&
        g_calls[i].payload_len && g_calls[i].payload[0] == 0x30)
      return g_calls[i].stream_id;
  return ~(u64)0;
}

/* A continues its keep-open stream sid with Object {g, o} of n bytes. */
static void mfill_obj_more(u64 sid, u64 g, u64 o, usz n) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u8  pl[MOQTRUN_TEST_MAX_PAYLOAD];
  usz off = 0;
  for (usz i = 0; i < n; i++) pl[i] = (u8)(16 * g + o);
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, o, wired_span_of(pl, n));
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(buf, off), 0);
}

/* One parked fill round and one parked (ring-held) live round for the
 * same subscriber, both released by the next tick: descending decides
 * who goes first. Returns the publisher's keep-open stream id. */
static void mfill_sched_fixture(int descending, u64* fill_sid, u64* live_sid) {
  moqfetch_fill fill = {0};
  fill.descending    = (u8)descending;
  mf_init(sizeof mf_arena);
  mtst_hub.reliable_alias_limit = 100; /* alice's alias 1: ring-backed */
  mf_obj(0, 0, 1);
  g_stream_send_ok_n = 0; /* opens pass, data rounds park */
  moqctl_params sub  = mfill_params(&fill, 0);
  mfill_subscribe_req(&sub);
  u64 pub_sid = mf_obj_on(1, 0, 1, 0); /* keep-open: ring relay to B */
  mfill_obj_more(pub_sid, 1, 1, 1);    /* refused round, held in the ring */
  *fill_sid          = mfill_sid(0);
  *live_sid          = mfill_relay_sid();
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 5);
}

/* An ascending fill with Objects ready goes out before the same
 * subscription's pending live round (draft-22 9.20.15: the backlog is
 * what the subscriber is still catching up on). */
static void test_moqtrun_fill_ascending_sends_first(void) {
  u64 fill_sid, live_sid;
  mfill_sched_fixture(0, &fill_sid, &live_sid);
  CHECK(mfill_send_idx(fill_sid) != ~(usz)0);
  CHECK(mfill_send_idx(live_sid) != ~(usz)0);
  CHECK(mfill_send_idx(fill_sid) < mfill_send_idx(live_sid));
}

/* A descending fill yields: the live round goes out first (the
 * subscriber wants the newest edge before the deep backlog). */
static void test_moqtrun_fill_descending_sends_last(void) {
  u64 fill_sid, live_sid;
  mfill_sched_fixture(1, &fill_sid, &live_sid);
  CHECK(mfill_send_idx(fill_sid) != ~(usz)0);
  CHECK(mfill_send_idx(live_sid) != ~(usz)0);
  CHECK(mfill_send_idx(live_sid) < mfill_send_idx(fill_sid));
}

/* A fill that cannot even open never starves the live side: the held
 * fill stays silent and the ring-held live round still goes out. */
static void test_moqtrun_fill_blocked_never_starves_live(void) {
  moqfetch_fill fill = {0};
  mf_init(sizeof mf_arena);
  mtst_hub.reliable_alias_limit = 100;
  mf_obj(0, 0, 1);
  mfill_subscribe_req(0);
  u64 pub_sid       = mf_obj_on(1, 0, 1, 0); /* relay to B opens first */
  u64 live_sid      = mfill_relay_sid();
  g_open_uni_fail_n = 100; /* from here only the fill's open is refused */
  mfill_update(&fill, 0);  /* the fill is held unopened */
  g_stream_send_ok_n = 0;
  mfill_obj_more(pub_sid, 1, 1, 1);
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 5);
  CHECK(mfill_send_idx(live_sid) != ~(usz)0); /* live went out */
  CHECK(!mf_no_fetch());                      /* the fill is still held */
}

/* s delivers a fetch data stream (FETCH_HEADER naming rid) on a fresh
 * client uni stream sid. */
static void mfill_inbound_fetch(wired_wt_session* s, u64 sid, u64 rid) {
  u8  buf[32];
  usz n = 0;
  CHECK(moqfetch_hdr_put(wired_mspan_of(buf, sizeof buf), &n, rid));
  wired_moqt_on_stream_data(&mtst_hub, s, sid, wired_span_of(buf, n), 0);
}

/* An inbound fetch stream naming the Request ID of the peer's own
 * PUBLISH is accepted against that track: no STOP_SENDING, no reset,
 * and the session stays open (draft-22 11.4.4 routing by Request ID). */
static void test_moqtrun_fill_inbound_fetch_known_rid(void) {
  mf_init(sizeof mf_arena);
  u64 pub_rid = mtst_rid; /* A's PUBLISH claimed its track with it */
  moqtrun_test_reset();
  mfill_inbound_fetch(SESS_A, 4002, pub_rid);
  CHECK(moqtrun_test_count_kind(13) == 0);
  CHECK(moqtrun_test_count_kind(7) == 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A) != 0);
}

/* Any other Request ID -- unroutable, or from a peer that PUBLISHed
 * nothing -- is answered STOP_SENDING on that one stream; the session
 * is never closed over it. */
static void test_moqtrun_fill_inbound_fetch_unknown_rid(void) {
  mf_init(sizeof mf_arena);
  moqtrun_test_reset();
  mfill_inbound_fetch(SESS_A, 4002, 9999);
  CHECK(moqtrun_test_count_kind(13) == 1);
  CHECK(moqtrun_test_last_kind(13)->stream_id == 4002);
  CHECK(moqtrun_test_count_kind(11) == 0);
  mfill_inbound_fetch(SESS_B, 4006, 9999); /* B published nothing */
  CHECK(moqtrun_test_count_kind(13) == 2);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A) != 0);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_B) != 0);
}

void test_moqtrun_fill(void) {
  test_moqtrun_fill_subscribe_opens();
  test_moqtrun_fill_end_clipped_to_largest();
  test_moqtrun_fill_empty_or_future_range();
  test_moqtrun_fill_open_end_is_largest();
  test_moqtrun_fill_update_opens();
  test_moqtrun_fill_forward_gates();
  test_moqtrun_fill_two_at_once();
  test_moqtrun_fill_publish_started_sub();
  test_moqtrun_fill_miss_is_timed_out_now();
  test_moqtrun_fill_evicted_run_collapsed();
  test_moqtrun_fill_eviction_under_cursor();
  test_moqtrun_fill_descending();
  test_moqtrun_fill_descending_skips_gap();
  test_moqtrun_fill_next_object_no_gap();
  test_moqtrun_fill_update_overlap_dup();
  test_moqtrun_fill_stop_sending_leaves_sub();
  test_moqtrun_fill_cancel_resets_all();
  test_moqtrun_fill_stall_delivery_timeout();
  test_moqtrun_fill_blocked_open_held();
  test_moqtrun_fill_upstream_gone_resets();
  test_moqtrun_fill_blocked_upstream_gone();
  test_moqtrun_fill_counts_in_done();
  test_moqtrun_fill_done_waits_for_held();
  test_moqtrun_fill_slot_full_held();
  test_moqtrun_fill_slot_full_cancel_drops();
  test_moqtrun_fill_slot_full_done_waits();
  test_moqtrun_fill_ascending_sends_first();
  test_moqtrun_fill_descending_sends_last();
  test_moqtrun_fill_blocked_never_starves_live();
  test_moqtrun_fill_inbound_fetch_known_rid();
  test_moqtrun_fill_inbound_fetch_unknown_rid();
}
