#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_frag_pool_clear(wired_moqt_hub* hub);
static void moqtrun_fetch_arr_clear(wired_moqtrun_fetch* arr);
static void moqtrun_fetches_clear(wired_moqt_hub* hub);
static void moqtrun_hub_tracks_clear(wired_moqt_hub* hub);
static void moqtrun_hub_auth_clear(wired_moqt_hub* hub);
static void moqtrun_hub_relay_stats_clear(wired_moqt_hub* hub);
static void moqtrun_hub_rel_stats_clear(wired_moqt_hub* hub);
static void moqtrun_hub_pools_clear(wired_moqt_hub* hub);

static void moqtrun_frag_pool_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_FRAG_POOL; i++) hub->frag_owner[i] = 0;
}

static void moqtrun_fetch_arr_clear(wired_moqtrun_fetch* arr) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    arr[i].in_use       = 0;
    arr[i].wt           = 0;
    arr[i].up_state     = WIRED_MOQTRUN_UPF_NONE;
    arr[i].up_data_open = 0;
  }
}

static void moqtrun_fetches_clear(wired_moqt_hub* hub) {
  moqtrun_fetch_arr_clear(hub->fetches);
  moqtrun_fetch_arr_clear(hub->fetch_waits);
  hub->upf_len   = 0;
  hub->upf_owner = 0;
}

static void moqtrun_hub_tracks_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    hub->peers[i].in_use = 0;
    moqtrun_peer_clear_relays(&hub->peers[i]);
  }
  moqtrun_track_clear_relays(&hub->blob_track);
  moqtrun_track_clear_relays(&hub->live.track);
  hub->blob_track.subgroup_timeout_ms = 0; /* no PUBLISH property sets it */
  hub->live.track.subgroup_timeout_ms = 0;
  hub->blob_track.in_use              = 0;
  hub->live.track.in_use              = 0;
  hub->live.last_now_ms               = 0;
}

static void moqtrun_hub_auth_clear(wired_moqt_hub* hub) {
  hub->authorize_subscribe = 0;
  hub->authorize_ctx       = 0;
  hub->authorize_publish   = 0;
  hub->authorize_pub_ctx   = 0;
  hub->authorize_namespace = 0;
  hub->authorize_ns_ctx    = 0;
  hub->raw_policy          = (moqraw_policy){0};
}

static void moqtrun_hub_relay_stats_clear(wired_moqt_hub* hub) {
  hub->stat_frag_drop   = 0;
  hub->stat_relay_sent  = 0;
  hub->stat_relay_drop  = 0;
  hub->stat_open_drop   = 0;
  hub->stat_relay_reset = 0;
  hub->stat_relay_full  = 0;
  hub->stat_dg_sent     = 0;
  hub->stat_dg_drop     = 0;
  hub->stat_dg_bad      = 0;
  hub->stat_live_sent   = 0;
  hub->stat_live_drop   = 0;
}

static void moqtrun_hub_rel_stats_clear(wired_moqt_hub* hub) {
  hub->stat_rel_stall        = 0;
  hub->stat_timeout_reset    = 0;
  hub->stat_rel_overflow     = 0;
  hub->stat_rel_wait         = 0;
  hub->stat_rel_sent         = 0;
  hub->stat_rel_refused      = 0;
  hub->stat_rel_rings        = 0;
  hub->stat_rel_in_bytes     = 0;
  hub->stat_rel_fin_in       = 0;
  hub->stat_rel_fin_out      = 0;
  hub->stat_rel_hold         = 0;
  hub->stat_rel_early_return = 0;
}

static void moqtrun_hub_pools_clear(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTREL_POOL; i++) moqtrel_reset(&hub->rel_pool[i]);
  moqtss_hub_init(hub); /* SSTS (moqtssts_run.c): off */
  moqtrun_reqs_clear(hub);
  moqtrun_rdv_clear(hub);
  moqtrun_up_clear(hub);
  moqtrun_frag_pool_clear(hub);
  moqcache_init(&hub->cache, 0, 0);
  hub->cache_tag_next = 0;
  moqtrun_fetches_clear(hub);
}

void wired_moqt_init(wired_moqt_hub* hub, wired_moqt_io io) {
  moqtrun_hub_tracks_clear(hub);
  moqtrun_hub_auth_clear(hub);
  moqtrun_hub_relay_stats_clear(hub);
  moqtrun_hub_rel_stats_clear(hub);
  moqtrun_hub_pools_clear(hub);
  hub->io                   = io;
  hub->join_seq_next        = 0;
  hub->reliable_alias_limit = 0;
  hub->newest_group_only    = 0;
  hub->switch_track         = 0; /* SWITCH_FROM (moqtswitch.c): off */
  hub->sw_live              = 0;
}
