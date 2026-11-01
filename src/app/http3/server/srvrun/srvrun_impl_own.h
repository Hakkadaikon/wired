#ifndef WIRED_SRVRUN_IMPL_OWN_H
#define WIRED_SRVRUN_IMPL_OWN_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvrun/srvrun.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/keys/ticket/ticket.h"
#include "transport/conn/cid/sreset/sreset.h"
#include "transport/packet/header/packet/header.h"

/* Byte capacity of the owned certificate chain: the certificate loader's
 * own store (wired_certreload_store.chain_der) holds at most this much, so
 * every chain the SDK can load from PEM fits; a larger hand-built chain is
 * refused at start. */
#define SRVRUN_OWN_CHAIN_CAP 16384

/* Byte capacity of one owned space-separated id list (raw_alpns,
 * wt_protocols), NUL included: room for two maximal 255-byte RFC 7301
 * protocol ids and a separator. Real lists are a few short ids
 * ("moqt-22 moqt-19 moqt-18"). */
#define SRVRUN_OWN_LIST_CAP 512

/* Byte capacity of one owned path (qlog, keylog, cert, key), NUL
 * included: Linux PATH_MAX. */
#define SRVRUN_OWN_PATH_CAP 4096

/* Issue #182: the run's own copy of everything the application handed in
 * by pointer (wired_srvboot_id's keys, ids and chain, the obs paths, the
 * WebTransport subprotocol list). Each boot reads its id long after
 * wired_srvrun_serve_env was called, so a view into the caller's memory
 * would dangle the moment that memory went out of scope; the copy is made
 * once at start (srvrun_own_config), never per connection or packet.
 * views: chain=slot */
typedef struct {
  wired_srvboot_id id;
  u8               priv[32];
  u8               pub[32];
  u8               cert_seed[32];
  u8               scid[WIRED_MAX_CID_LEN];
  u8               random[32];
  u8               san_ipv4[4];
  u8               retry_odcid[WIRED_MAX_CID_LEN];
  u8               ticket_key[TICKET_KEY_LEN];
  u8               pref_v4[4];
  u8               pref_v6[16];
  u8               reset_seed[SRESET_KEY];
  wired_span       chain[TLS_CERT_CHAIN_MAX];
  u8               chain_der[SRVRUN_OWN_CHAIN_CAP];
  char             raw_alpns[SRVRUN_OWN_LIST_CAP];
  char             wt_protocols[SRVRUN_OWN_LIST_CAP];
  char             qlog_path[SRVRUN_OWN_PATH_CAP];
  char             keylog_path[SRVRUN_OWN_PATH_CAP];
  char             cert_path[SRVRUN_OWN_PATH_CAP];
  char             key_path[SRVRUN_OWN_PATH_CAP];
} srvrun_own;

/* Issue #182: copy *id, obs's paths and *wt_protocols into env->own and
 * point them there; 0 (nothing to serve) when one does not fit. */
int srvrun_own_config(
    wired_srvrun_env*  env,
    wired_srvboot_id** id,
    wired_srvrun_obs*  obs,
    const char**       wt_protocols);

/* dst holding a copy of src (NUL included), or 0 when src is 0; *ok = 0
 * when it does not fit in cap bytes (srvrun_own_str.c). */
const char* srvrun_own_str(char* dst, usz cap, const char* src, int* ok);

/* Copy obs's paths into o and point obs there; *ok = 0 when one does not
 * fit (srvrun_own_str.c). */
void srvrun_own_obs(srvrun_own* o, wired_srvrun_obs* obs, int* ok);

#endif
