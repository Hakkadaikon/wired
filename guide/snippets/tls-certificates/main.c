#define WIRED_MAIN
#include "wired.h"

static int fail(const char* msg) {
  wired_log_str(msg);
  return 1;
}

int wired_main(int argc, char** argv) {
  static u8 text[8192], der[4096];
  if (argc < 3) return fail("usage: tls-certificates cert.pem key.pem\n");

  /* Walk every PEM block of cert.pem, decoding each to DER. */
  wired_span pem =
      wired_fio_read_span(argv[1], wired_mspan_of(text, sizeof text));
  if (pem.n == 0) return fail("cannot read cert.pem\n");
  usz        at = 0;
  wired_span label;
  wired_obuf out = {der, sizeof der, 0};
  for (usz start = 0; wired_pem_next(pem, &at, &label, &out); start = out.len) {
    wired_dprintf(
        2, "block %.*s len=%llu\n", WIRED_SPAN_ARG(label),
        (u64)(out.len - start));
  }

  /* key.pem holds one block: the P-256 private key (SEC1 or PKCS#8). */
  u8 priv[32];
  pem     = wired_fio_read_span(argv[2], wired_mspan_of(text, sizeof text));
  at      = 0;
  out.len = 0;
  if (!wired_pem_next(pem, &at, &label, &out) ||
      !wired_eckey_p256_priv(wired_span_of(der, out.len), priv))
    return fail("bad key\n");
  wired_log_str("key ok\n");

  /* certreload does all of the above in one call and fills a server
   * identity; the store must outlive the identity. */
  static wired_certreload_store store;
  wired_srvboot_id              id = {0};
  if (!wired_certreload_load(argv[1], argv[2], &store, &id))
    return fail("load failed\n");
  wired_dprintf(2, "load ok: %llu certificate(s)\n", (u64)id.chain_count);
  return 0;
}
