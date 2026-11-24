/* libFuzzer harness for the NIP-98 token checker: raw JSON or
 * "Nostr <base64>" tokens through parse, tag / window checks, id and
 * BIP-340 verification, then the replay cache (fixed request; the first
 * input byte picks whether a body hash is required and the clock). The
 * cache is small and kept across inputs (reset every 4096) so SEEN and
 * FULL are reachable. Hosted build only —
 * mirrors tests/run.c's unity-include style, but this file itself may use
 * the standard library since it lives outside src/. Seeds:
 * fuzz/corpus/fuzz_nip98/. */
#include <stddef.h>
#include <stdint.h>

#define NIP98_REPLAY_CAP 8

#include "app/nostr/event/nostrev_esc.c"
#include "app/nostr/event/nostrev_lex.c"
#include "app/nostr/event/nostrev_list.c"
#include "app/nostr/event/nostrev_obj.c"
#include "app/nostr/event/nostrev_ser.c"
#include "app/nostr/event/nostrev_tags.c"
#include "app/nostr/event/nostrev_utf8.c"
#include "app/nostr/nip98/nip98.c"
#include "app/nostr/nip98/nip98_replay.c"
#include "app/nostr/nip98/nip98_tag.c"
#include "common/bytes/text/text.c"
#include "common/platform/debug/debug.c"
#include "crypto/asymmetric/ecc/bip340/bip340.c"
#include "crypto/asymmetric/ecc/p256/p256_field.c"
#include "crypto/asymmetric/ecc/p256/p256_field_fe.c"
#include "crypto/asymmetric/ecc/p256/p256_field_fp.c"
#include "crypto/asymmetric/ecc/p256/p256_field_mont.c"
#include "crypto/asymmetric/ecc/p256/p256_field_p256.c"
#include "crypto/asymmetric/ecc/p256/p256_field_p256_fp.c"
#include "crypto/asymmetric/ecc/secp256k1/secp256k1_field.c"
#include "crypto/asymmetric/ecc/secp256k1/secp256k1_mul.c"
#include "crypto/asymmetric/ecc/secp256k1/secp256k1_point.c"
#include "crypto/pki/encoding/pem/pem.c"
#include "crypto/pki/encoding/pem/pem_emit.c"
#include "crypto/symmetric/hash/hash/sha256.c"

static u8           fz_buf[2 * NOSTREV_MAX_JSON];
static nostrev      fz_ev;
static nip98_replay fz_rc;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static const u8 hash[32] = {0};
  static usz      runs;
  nip98_verdict   v;
  nip98_req       rq = {
      .url    = wired_span_of((const u8*)"https://hub.example/moq?room=r1", 31),
      .method = wired_span_of((const u8*)"CONNECT", 7),
      .now    = 1732400000,
      .replay = &fz_rc,
  };
  if (size == 0) {
    return 0;
  }
  if (runs++ % 4096 == 0) {
    nip98_replay_init(&fz_rc, 0);
  }
  rq.body_hash = (data[0] & 1) ? hash : 0;
  rq.now += data[0] >> 1;
  v = nip98_check(
      &rq, wired_span_of((const u8*)data + 1, (usz)size - 1), &fz_ev, fz_buf,
      sizeof(fz_buf));
  /* Harness only: also admit ids that failed the id / signature check, so
   * fuzzer-chosen ids fill the cache. Production admits after NIP98_OK and
   * the caller's authorisation only. */
  if (v == NIP98_OK || v >= NIP98_BAD_ID) {
    (void)nip98_replay_admit(&fz_rc, fz_ev.id, fz_ev.created_at, rq.now);
  }
  return 0;
}
