#define WIRED_MAIN
#include "wired.h"

/* A real browser dialing WebTransport by IP (no DNS name) needs three
 * things from the server identity: a SAN IP address entry in the self-
 * signed cert (RFC 5280 4.2.1.6), a validity window the cert is actually
 * inside of (now_secs), and the cert's SHA-256 to pin via
 * serverCertificateHashes. now_secs=0 keeps the SDK's fixed 2020-2030
 * window, so this demo stays deterministic without a real clock. */
static const u8 SAN_IPV4[4] = {127, 0, 0, 1};

/* SHA-256 the exact certificate DER this identity serves (built the same
 * way srvboot builds it for every connection) and log it as the colon-hex
 * fingerprint a browser pins via serverCertificateHashes. */
static void log_cert_fingerprint(const wired_srvboot_id* id) {
  static wired_server  s; /* throwaway, kept off the stack */
  wired_server_init_in in = {id->priv,    id->pub,         id->cert_seed,
                             id->chain,   id->chain_count, id->san_ipv4,
                             id->now_secs, 0};
  u8                   digest[32];

  wired_server_init(&s, &in);
  wired_sha256(s.sdrv.certs[0].p, s.sdrv.certs[0].n, digest);

  wired_dprintf(2, "cert sha-256 fingerprint: ");
  for (usz i = 0; i < 32; i++) wired_dprintf(2, i ? ":%02x" : "%02x", digest[i]);
  wired_dprintf(2, "\n");
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-wt";
  wired_srvboot_id id = {0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  id.priv                    = priv;
  id.pub                     = pub;
  id.cert_seed                = seed;
  id.random                   = rnd;
  id.scid                     = scid;
  id.scid_len                 = sizeof scid - 1; /* without the string's NUL */
  id.max_datagram_frame_size  = 65535; /* WebTransport requires DATAGRAM */
  id.san_ipv4                 = SAN_IPV4;
  id.now_secs                 = 0; /* the SDK's fixed 2020-2030 window */
  log_cert_fingerprint(&id);

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
