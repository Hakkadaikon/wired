#ifndef APP_NOSTR_NIP98_NIP98_H
#define APP_NOSTR_NIP98_NIP98_H

/* NIP-98 HTTP Auth token check: the token is a kind 27235 event, as raw
 * JSON or as "Nostr <base64(JSON)>" (scheme case-insensitive, RFC 9110
 * 11.1). Checks, in order (cheap ones before the BIP-340 verification):
 * parse (NIP-01 subset, see nostrev.h), kind, created_at within +-window
 * of now, exactly one "u" tag equal to url byte for byte, exactly one
 * "method" tag equal to method, the "payload" tag (only when body_hash is
 * given: lowercase hex of it), id, then signature. It does NOT admit the
 * id to the replay cache: the caller authorises ev's pubkey first and then
 * calls nip98_replay_admit (see nip98_replay.h for why and the order). */

#include "app/nostr/event/nostrev.h"
#include "app/nostr/nip98/nip98_replay.h"
#include "common/bytes/span/span.h"

#define NIP98_KIND 27235

typedef enum {
  NIP98_OK = 0,
  NIP98_MALFORMED,   /* not a parseable event (or bad base64 / buffer) */
  NIP98_BAD_KIND,    /* kind != 27235 */
  NIP98_EXPIRED,     /* created_at outside now +- window */
  NIP98_BAD_U,       /* no / several / different "u" tag */
  NIP98_BAD_METHOD,  /* no / several / different "method" tag */
  NIP98_BAD_PAYLOAD, /* body_hash given, payload tag absent or different */
  NIP98_BAD_ID,      /* id is not the hash of the canonical form */
  NIP98_BAD_SIG,     /* BIP-340 signature fails */
} nip98_verdict;

/* views: url=caller, method=caller, body_hash=caller, replay=caller */
typedef struct {
  wired_span url;       /* expected "u" value */
  wired_span method;    /* expected "method" value */
  const u8*  body_hash; /* SHA-256 of the body, or 0: payload ignored */
  u64        now;       /* unix seconds */
  /* The replay cache the caller will admit to; only its window is read
   * here (required, so both checks share one window). */
  const nip98_replay* replay;
} nip98_req;

/* Check token against rq. ev receives the parsed event (its pubkey is the
 * authenticated identity on NIP98_OK); buf[0..cap) holds the base64-decoded
 * JSON and the decoded strings (2 x token length always suffices). */
nip98_verdict nip98_check(
    const nip98_req* rq, wired_span token, nostrev* ev, u8* buf, usz cap);

#endif
