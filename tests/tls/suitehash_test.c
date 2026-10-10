#include "test.h"

/* RFC 8446 7.1 / RFC 9001 5.1 key schedule under TLS_AES_256_GCM_SHA384.
 * No official SHA-384 QUIC vector exists, so every expected value below was
 * computed with an independent Python hashlib/hmac HKDF (whose SHA-256 form
 * reproduces RFC 9001 A.1's client_initial_secret c00cf151...7aea).
 * Inputs: ECDHE = 0x11 x 32, PSK = 0x22 x 48, transcript messages "abc". */

static void sh_hex(const char* hex, u8* out, usz n) {
  for (usz i = 0; i < n; i++) {
    u8 hi = (u8)hex[2 * i], lo = (u8)hex[2 * i + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

static int sh_eq(const u8* got, const char* hex, usz n) {
  u8 want[64];
  sh_hex(hex, want, n);
  for (usz i = 0; i < n; i++)
    if (got[i] != want[i]) return 0;
  return 1;
}

#define SH_HS                                                             \
  "32e0915f02d19589deae0b432931d3b57254ba9022b95b1f1d54446730889be863a1d" \
  "3a86165f68e02b2a06447734f81"
#define SH_CTS                                                            \
  "b0e8e86ea7ea5b0831aba4e30c04313b285d91b18b211a26944c4830e3b94622fd5d3" \
  "5598b07c453538ae0b6369c741c"
#define SH_MASTER                                                         \
  "44de65fc83862a80c2fa6fe3f6bba2a81117f9dc906bb716117215a009eeaa34a0876" \
  "aaaa837f60e4508d16578848a88"
#define SH_CAP                                                            \
  "316e87bf14a02b563fab1254811f61b6ffc3745cc220e280488dc378cea44c588a067" \
  "6d0c0f594219b80c3093533b3f9"

static void test_suitehash_select(void) {
  CHECK(tls_hash_of(TLS_AES_256_GCM_SHA384)->len == 48);
  CHECK(tls_hash_of(TLS_AES_128_GCM_SHA256)->len == 32);
  CHECK(tls_hash_of(TLS_CHACHA20_POLY1305_SHA256)->len == 32);
}

static void test_suitehash_secrets(void) {
  u8 ecdhe[32], psk[48], out[48], hs[48];
  for (usz i = 0; i < 32; i++) ecdhe[i] = 0x11;
  for (usz i = 0; i < 48; i++) psk[i] = 0x22;
  tls_handshake_secret_suite(TLS_AES_256_GCM_SHA384, ecdhe, hs);
  CHECK(sh_eq(hs, SH_HS, 48));
  tls_handshake_secret_psk_suite(TLS_AES_256_GCM_SHA384, psk, ecdhe, out);
  CHECK(sh_eq(
      out,
      "e03182b9e73ac7f9019ac1276d3722c772e2627edd74c20e4ce9b2a5e6e8c3f030cd3c"
      "292cb54d51cd69b5e4d261a2aa",
      48));
  derive_secret_in dsi = {
      hs, wired_span_of((const u8*)"c hs traffic", 12),
      wired_span_of((const u8*)"abc", 3), TLS_AES_256_GCM_SHA384};
  CHECK(tls_derive_secret(&dsi, out) == 1);
  CHECK(sh_eq(out, SH_CTS, 48));
  tls_master_secret_suite(TLS_AES_256_GCM_SHA384, hs, out);
  CHECK(sh_eq(out, SH_MASTER, 48));
}

static void test_suitehash_keys(void) {
  u8           hs[48], master[48];
  initial_keys k;
  sh_hex(SH_HS, hs, 48);
  sh_hex(SH_MASTER, master, 48);
  handshake_keys_in hin = {hs, wired_span_of((const u8*)"abc", 3), 0, 0};
  tls_handshake_keys_suite(&hin, TLS_AES_256_GCM_SHA384, &k);
  CHECK(sh_eq(
      k.key, "19111ae1c8b8fb8b4e46ce8a37c7cd444edd7a0e555f6e1a051b8044c1fdec49",
      32));
  CHECK(sh_eq(k.iv, "ae0514a2ea15878793d3b507", 12));
  CHECK(sh_eq(
      k.hp, "fa7c6c80e777fdc3658112dae709fbc7c3dd1f261dcb41ed613f77cebe50b597",
      32));
  app_keys_in ain = {master, wired_span_of((const u8*)"abc", 3), 0, 0};
  tls_app_keys_suite(&ain, TLS_AES_256_GCM_SHA384, &k);
  CHECK(sh_eq(
      k.key, "204d162bd886159f34685f9ce98f7edfc78533629d743a8167a6c2e2c0531f67",
      32));
  CHECK(sh_eq(k.iv, "f7c7ff81da201592eb9c3a86", 12));
  CHECK(sh_eq(
      k.hp, "24a9f330f27e08d8a48ea3ac9389b470ad94049f6c878553dda3177f8a612a20",
      32));
}

static void test_suitehash_finished_binder(void) {
  u8 cts[48], th[48], out[48], psk[48];
  sh_hex(SH_CTS, cts, 48);
  sha384((const u8*)"abc", 3, th);
  tls_finished_verify_data_suite(TLS_AES_256_GCM_SHA384, cts, th, out);
  CHECK(sh_eq(
      out,
      "98f998540e041879130bb7530c195cc437b842bd2d3b7eec2d1b8544c4dd3fc7935eb7"
      "982fb8ff1fc8a39c4219ec4054",
      48));
  CHECK(tls_finished_check_suite(TLS_AES_256_GCM_SHA384, cts, th, out) == 1);
  out[47] ^= 1;
  CHECK(tls_finished_check_suite(TLS_AES_256_GCM_SHA384, cts, th, out) == 0);
  for (usz i = 0; i < 48; i++) psk[i] = 0x22;
  tls_binder_compute_suite(
      TLS_AES_256_GCM_SHA384, psk, wired_span_of((const u8*)"trunc", 5), out);
  CHECK(sh_eq(
      out,
      "965596457085e86632024e7add54a620acbac288a18635c2edd7a565c5c62b36d0e069"
      "f5975e360c83022087b16941db",
      48));
  CHECK(
      tls_binder_verify_suite(
          TLS_AES_256_GCM_SHA384, psk, wired_span_of((const u8*)"trunc", 5),
          out) == 1);
  out[0] ^= 1;
  CHECK(
      tls_binder_verify_suite(
          TLS_AES_256_GCM_SHA384, psk, wired_span_of((const u8*)"trunc", 5),
          out) == 0);
}

static void test_suitehash_early_exporter_ku(void) {
  u8           psk[48], master[48], cap[48], out[48];
  initial_keys k;
  for (usz i = 0; i < 48; i++) psk[i] = 0x22;
  tls_early_keys_suite(TLS_AES_256_GCM_SHA384, psk, (const u8*)"CH", 2, &k);
  CHECK(sh_eq(
      k.key, "0ddb01db7bb67e4d1b1e933a8e10de8a118941dba994014723230a51a76cd158",
      32));
  CHECK(sh_eq(k.iv, "2973caabbb3bb46421b3622b", 12));
  sh_hex(SH_MASTER, master, 48);
  tls_exporter_master_secret_suite(
      TLS_AES_256_GCM_SHA384, master, (const u8*)"abc", 3, out);
  CHECK(sh_eq(
      out,
      "ed3a843fb66b5ef23d4c58d4581eeaebb7b72e23a1ef8f8f24f255805afbcdc8cac8ba"
      "e0bf0542152fad9e8ca12a994c",
      48));
  /* RFC 9001 6.1: secret_1 = HKDF-Expand-Label(secret_0, "quic ku", "",
   * Hash.length), key/iv re-derived from it, hp kept. */
  sh_hex(SH_CAP, cap, 48);
  for (usz i = 0; i < 32; i++) k.hp[i] = 0x5a;
  kuswitch_next_keys_suite(TLS_AES_256_GCM_SHA384, cap, &k, out);
  CHECK(sh_eq(
      out,
      "29adfb19d56cba4300692775cb0efb2280b406dc657cf11a65fd0c080ef89949c3abcf"
      "e5f3a1748939d952ca2f9ed53f",
      48));
  CHECK(sh_eq(
      k.key, "de1123b88e43367c6cbce9a77d4344511c6c47c8be118ac684c6068903476804",
      32));
  CHECK(sh_eq(k.iv, "c2dfc84a74b8d1e3176f7b06", 12));
  CHECK(k.hp[31] == 0x5a);
}

void test_suitehash(void) {
  test_suitehash_select();
  test_suitehash_secrets();
  test_suitehash_keys();
  test_suitehash_finished_binder();
  test_suitehash_early_exporter_ku();
}
