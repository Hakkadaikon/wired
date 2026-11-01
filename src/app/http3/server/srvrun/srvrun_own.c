#include "app/http3/server/srvrun/srvrun_impl.h"

static const u8* srvrun_own_bytes(u8* dst, const u8* src, usz n);
static usz       srvrun_own_chain_len(const wired_srvboot_id* id);
static int       srvrun_own_chain(srvrun_own* o, const wired_srvboot_id* id);
static void      srvrun_own_keys(srvrun_own* o, const wired_srvboot_id* id);
static void      srvrun_own_addrs(srvrun_own* o, const wired_srvboot_id* id);
static int       srvrun_own_sizes_ok(const wired_srvboot_id* id);

/* dst holding a copy of the n bytes at src, or 0 when src is 0 (absent). */
static const u8* srvrun_own_bytes(u8* dst, const u8* src, usz n) {
  if (!src) {
    return 0;
  }
  bytes_memcpy(dst, src, n);
  return dst;
}

/* id's external chain entries: none when it names no chain, as sdrv
 * reads a chain-less id (self-signed). */
static usz srvrun_own_count(const wired_srvboot_id* id) {
  return id->chain ? id->chain_count : 0;
}

/* Total DER bytes of id's chain, past SRVRUN_OWN_CHAIN_CAP when it does not
 * fit: too many entries, or too many bytes (each entry is clamped first, so
 * the sum cannot wrap). */
static usz srvrun_own_chain_len(const wired_srvboot_id* id) {
  usz n = 0;
  if (srvrun_own_count(id) > TLS_CERT_CHAIN_MAX) {
    return SRVRUN_OWN_CHAIN_CAP + 1;
  }
  for (usz i = 0; i < srvrun_own_count(id); i++) {
    n += (usz)u64_min(id->chain[i].n, SRVRUN_OWN_CHAIN_CAP + 1);
  }
  return n;
}

/* Copy id's external chain (none: self-signed) into o->chain_der, one view
 * per entry. 0 when it has too many entries or bytes. */
static int srvrun_own_chain(srvrun_own* o, const wired_srvboot_id* id) {
  usz at = 0;
  if (srvrun_own_chain_len(id) > SRVRUN_OWN_CHAIN_CAP) {
    return 0;
  }
  o->id.chain_count = srvrun_own_count(id);
  for (usz i = 0; i < o->id.chain_count; i++) {
    bytes_memcpy(o->chain_der + at, id->chain[i].p, id->chain[i].n);
    o->chain[i] = wired_span_of(o->chain_der + at, id->chain[i].n);
    at += id->chain[i].n;
  }
  o->id.chain = o->chain;
  return 1;
}

/* The key material and per-run secrets. */
static void srvrun_own_keys(srvrun_own* o, const wired_srvboot_id* id) {
  o->id.priv      = srvrun_own_bytes(o->priv, id->priv, sizeof o->priv);
  o->id.pub       = srvrun_own_bytes(o->pub, id->pub, sizeof o->pub);
  o->id.cert_seed = srvrun_own_bytes(o->cert_seed, id->cert_seed, 32);
  o->id.random    = srvrun_own_bytes(o->random, id->random, sizeof o->random);
  o->id.ticket_key =
      srvrun_own_bytes(o->ticket_key, id->ticket_key, TICKET_KEY_LEN);
  o->id.reset_seed =
      srvrun_own_bytes(o->reset_seed, id->reset_seed, SRESET_KEY);
}

/* The connection ids and addresses. */
static void srvrun_own_addrs(srvrun_own* o, const wired_srvboot_id* id) {
  o->id.scid = srvrun_own_bytes(o->scid, id->scid, id->scid_len);
  o->id.san_ipv4 =
      srvrun_own_bytes(o->san_ipv4, id->san_ipv4, sizeof o->san_ipv4);
  o->id.retry_odcid =
      srvrun_own_bytes(o->retry_odcid, id->retry_odcid, id->retry_odcid_len);
  o->id.pref_v4 = srvrun_own_bytes(o->pref_v4, id->pref_v4, sizeof o->pref_v4);
  o->id.pref_v6 = srvrun_own_bytes(o->pref_v6, id->pref_v6, sizeof o->pref_v6);
}

/* The variable-length ids fit their owned arrays (scid_len was already
 * checked by srvrun_can_serve). */
static int srvrun_own_sizes_ok(const wired_srvboot_id* id) {
  return id->retry_odcid_len <= WIRED_MAX_CID_LEN;
}

int srvrun_own_config(
    wired_srvrun_env*  env,
    wired_srvboot_id** id,
    wired_srvrun_obs*  obs,
    const char**       wt_protocols) {
  srvrun_own* o  = &env->own;
  int         ok = srvrun_own_sizes_ok(*id);
  if (!ok) {
    return 0;
  }
  o->id = **id;
  srvrun_own_keys(o, *id);
  srvrun_own_addrs(o, *id);
  ok = srvrun_own_chain(o, *id);
  o->id.raw_alpns =
      srvrun_own_str(o->raw_alpns, sizeof o->raw_alpns, (*id)->raw_alpns, &ok);
  *wt_protocols = srvrun_own_str(
      o->wt_protocols, sizeof o->wt_protocols, *wt_protocols, &ok);
  srvrun_own_obs(o, obs, &ok);
  *id = &o->id;
  return ok;
}

const wired_srvboot_id* wired_server_run_id(void) {
  return &srvrun_caller_env()->own.id;
}
