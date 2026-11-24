/* libFuzzer harness for the NIP-01 event parser (strict JSON subset) and,
 * on a parsed event, the canonical serialisation and full verification
 * (id + BIP-340 over secp256k1). Hosted build only — mirrors tests/run.c's
 * unity-include style, but this file itself may use the standard library
 * since it lives outside src/. Seeds: fuzz/corpus/fuzz_nostrev/. */
#include <stddef.h>
#include <stdint.h>

#include "app/nostr/event/nostrev_esc.c"
#include "app/nostr/event/nostrev_lex.c"
#include "app/nostr/event/nostrev_list.c"
#include "app/nostr/event/nostrev_obj.c"
#include "app/nostr/event/nostrev_ser.c"
#include "app/nostr/event/nostrev_tags.c"
#include "app/nostr/event/nostrev_utf8.c"
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
#include "crypto/symmetric/hash/hash/sha256.c"

static u8      fz_buf[NOSTREV_MAX_JSON];
static nostrev fz_ev;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  usz n = (usz)size;
  /* Decoded strings never exceed the input, so a buffer of n bytes must
   * always suffice; a smaller one exercises the overflow path. */
  if (!nostrev_parse(
          &fz_ev, (const u8*)data, n, fz_buf,
          n < sizeof(fz_buf) ? n : sizeof(fz_buf))) {
    return 0;
  }
  (void)nostrev_verify(&fz_ev);
  return 0;
}
