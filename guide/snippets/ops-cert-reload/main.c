#define WIRED_MAIN
#include "crypto/symmetric/hash/hash/sha256.h"
#include "wired.h"

/* No HTTP traffic is expected: the client only completes the handshake. */
static int on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body_out,
    const char**                content_type,
    int*                        more,
    u64*                        total_size) {
  (void)ctx;
  (void)req;
  (void)offset;
  (void)body_out;
  (void)content_type;
  (void)more;
  (void)total_size;
  return 0;
}

/* Two self-signed PEM pairs. Neither is read from a committed file: the
 * reload path re-reads whatever is on disk at obs.cert_path, so this demo
 * writes live-cert.pem/live-key.pem itself (gitignored -- see
 * guide/.gitignore) instead of mutating a tracked file on every run. */
static const char CERT_A[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiTCCAS+gAwIBAgIUeFdWHBqqNDt3C3CLLSSpMDh8RwUwCgYIKoZIzj0EAwIw\n"
    "GTEXMBUGA1UEAwwOZ3VpZGUtcmVsb2FkLWEwIBcNMjYxMDAxMjMyMTM1WhgPMjEy\n"
    "NjA5MDcyMzIxMzVaMBkxFzAVBgNVBAMMDmd1aWRlLXJlbG9hZC1hMFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEU0zvYmyeYfEAjLRA3BeA3IcKoDr0mCvVp4JgzUNU\n"
    "DaHXcJfI/a40CH5G4DzJ82GXFMP+UzXLuk7i9RWLnEdC2aNTMFEwHQYDVR0OBBYE\n"
    "FHeW5daDJ8EO/Elx9j9swxTHX0nRMB8GA1UdIwQYMBaAFHeW5daDJ8EO/Elx9j9s\n"
    "wxTHX0nRMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJXh4tHM\n"
    "FpS7mPySnSkSYg0P2ERDp9qE3LWFFEAUx/Z2AiA9t1XB6HId5va//aCFqhaXLD1S\n"
    "qHtEqH+heW6zicxa2A==\n"
    "-----END CERTIFICATE-----\n";
static const char KEY_A[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIOGhRuYj1/POhZQ3lM8iy3xqCGISVDTCThg0SdWBfoCSoAoGCCqGSM49\n"
    "AwEHoUQDQgAEU0zvYmyeYfEAjLRA3BeA3IcKoDr0mCvVp4JgzUNUDaHXcJfI/a40\n"
    "CH5G4DzJ82GXFMP+UzXLuk7i9RWLnEdC2Q==\n"
    "-----END EC PRIVATE KEY-----\n";

/* The replacement PEM pair this demo "deploys" mid-run: an operator drops a
 * new PEM pair at the same path, then sends SIGHUP (RFC-agnostic Unix
 * convention, see certreload.h) so the already-running server picks it up
 * without dropping a single connection. */
static const char CERT_B[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiDCCAS+gAwIBAgIUDNBpuLap6FoZ0pPXHtBTdmm0BlMwCgYIKoZIzj0EAwIw\n"
    "GTEXMBUGA1UEAwwOZ3VpZGUtcmVsb2FkLWIwIBcNMjYxMDAxMjMyMTM1WhgPMjEy\n"
    "NjA5MDcyMzIxMzVaMBkxFzAVBgNVBAMMDmd1aWRlLXJlbG9hZC1iMFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEP91vAVpF32x51V8bqhHuu7/1yjUnLGJsiajGsWs+\n"
    "/dLUyNzPiJXkw8PZFh/MAbdvWZyLt83DpR0nh4KjlZ0y06NTMFEwHQYDVR0OBBYE\n"
    "FGq1lNRu98f48pv+7bpS+jj+QJK6MB8GA1UdIwQYMBaAFGq1lNRu98f48pv+7bpS\n"
    "+jj+QJK6MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgSgHhIxwv\n"
    "Sd5zoenlFXlhtK9XczJuFdlqmWqi+wQ1Nn8CIB12z2sKNZrDf4JSLq2Nag91ezcf\n"
    "piunBaTVKm4v8csC\n"
    "-----END CERTIFICATE-----\n";
static const char KEY_B[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIGNNehLgsRtYlrB+pS7qlz3pvyFWPCORkZ6NtYTF8LnnoAoGCCqGSM49\n"
    "AwEHoUQDQgAEP91vAVpF32x51V8bqhHuu7/1yjUnLGJsiajGsWs+/dLUyNzPiJXk\n"
    "w8PZFh/MAbdvWZyLt83DpR0nh4KjlZ0y0w==\n"
    "-----END EC PRIVATE KEY-----\n";

/* Logs the active leaf certificate's fingerprint once per change: the
 * baseline on the first tick, then again the moment a SIGHUP reload swaps
 * it. wired_main's `id` and this on_step's ctx are the SAME object the SDK
 * mutates in place on reload (srvrun.h), so reading id->chain[0] here always
 * reflects whichever PEM pair is currently loaded. */
static u8  g_last_fp[SHA256_DIGEST];
static int g_have_fp = 0;

static void report_cert(const wired_srvboot_id* id) {
  u8 fp[SHA256_DIGEST];
  wired_sha256(id->chain[0].p, id->chain[0].n, fp);
  if (g_have_fp &&
      wired_span_eq(
          wired_span_of(fp, sizeof fp), wired_span_of(g_last_fp, sizeof fp)))
    return;
  wired_log_str(g_have_fp ? "cert reloaded, leaf sha256=" : "leaf sha256=");
  wired_dump_hex(2, wired_span_of(fp, sizeof fp));
  wired_log_str("\n");
  memcpy(g_last_fp, fp, sizeof fp);
  g_have_fp = 1;
}

/* Writes live-cert.pem/live-key.pem's replacement once, early: the
 * already-running server keeps the identity it loaded at startup until a
 * SIGHUP arrives (srvrun.c re-reads only on signal), so doing this
 * immediately does not disturb the first handshake. */
static int g_deployed = 0;

static void deploy_cert_b(void) {
  if (g_deployed) return;
  g_deployed = 1;
  wired_fio_write_new(
      "live-cert.pem", wired_span_of((const u8*)CERT_B, sizeof CERT_B - 1));
  wired_fio_write_new(
      "live-key.pem", wired_span_of((const u8*)KEY_B, sizeof KEY_B - 1));
}

static void on_step(void* ctx, u64 now_ms) {
  (void)now_ms;
  deploy_cert_b();
  report_cert((const wired_srvboot_id*)ctx);
}

int wired_main(int argc, char** argv) {
  /* A fixed demo identity: X25519 key share, certificate signing seed,
   * connection id and ServerHello.random. live-cert.pem/live-key.pem (seeded
   * from CERT_A/KEY_A below, just above wired_main) hold the first
   * certificate. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-cr");

  wired_fio_write_new(
      "live-cert.pem", wired_span_of((const u8*)CERT_A, sizeof CERT_A - 1));
  wired_fio_write_new(
      "live-key.pem", wired_span_of((const u8*)KEY_A, sizeof KEY_A - 1));
  static wired_certreload_store store;
  wired_certreload_load_or_selfsigned(
      "live-cert.pem", "live-key.pem", &store, &id);

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;
  opt.on_step          = on_step;
  opt.on_step_ctx      = &id;

  wired_srvrun_obs obs = {0};
  obs.cert_path        = "live-cert.pem";
  obs.key_path         = "live-key.pem";

  u16 port               = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h = {.cb = on_request};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
