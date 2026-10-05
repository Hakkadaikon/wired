#define WIRED_MAIN
#include "wired.h"

/* label is a view into the PEM text, not NUL-terminated. */
static void log_span(wired_span s) {
  char c[2] = {0};
  for (usz i = 0; i < s.n; i++) {
    c[0] = (char)s.p[i];
    wired_log_str(c);
  }
}

static int fail(const char* msg) {
  wired_log_str(msg);
  return 1;
}

/* Read a whole file into buf; returns its contents as a span (n = 0 on
 * error). */
static wired_span read_file(const char* path, u8* buf, usz cap) {
  ssz n = wired_fio_read(path, wired_mspan_of(buf, cap));
  return wired_span_of(buf, n < 0 ? 0 : (usz)n);
}

int wired_main(int argc, char** argv) {
  static u8 text[8192], der[4096];
  if (argc < 3) return fail("usage: tls-certificates cert.pem key.pem\n");

  /* Walk every PEM block of cert.pem, decoding each to DER. */
  wired_span pem = read_file(argv[1], text, sizeof text);
  if (pem.n == 0) return fail("cannot read cert.pem\n");
  usz        at  = 0;
  wired_span label;
  wired_obuf out = {der, sizeof der, 0};
  for (usz start = 0; wired_pem_next(pem, &at, &label, &out); start = out.len) {
    wired_log_str("block ");
    log_span(label);
    wired_dprintf(2, " len=%llu\n", (u64)(out.len - start));
  }

  /* key.pem holds one block: the P-256 private key (SEC1 or PKCS#8). */
  u8 priv[32];
  pem     = read_file(argv[2], text, sizeof text);
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
