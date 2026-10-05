#define WIRED_MAIN
#include "wired.h"

/* A real browser dialing WebTransport by IP (no DNS name) needs three
 * things from the server identity: a SAN IP address entry in the self-
 * signed cert (RFC 5280 4.2.1.6), a validity window the cert is actually
 * inside of (now_secs), and the cert's SHA-256 to pin via
 * serverCertificateHashes. now_secs=0 keeps the SDK's fixed 2020-2030
 * window, so this demo stays deterministic without a real clock. */
static const u8 SAN_IPV4[4] = {127, 0, 0, 1};

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static wired_srvboot_demo_keys keys;
  wired_srvboot_id               id;
  wired_srvboot_demo(&id, &keys, 0x50, "guide-wt");
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */
  id.san_ipv4                = SAN_IPV4;
  id.now_secs                = 0; /* the SDK's fixed 2020-2030 window */
  wired_srvboot_log_fingerprint(2, &id);

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu     = -1;

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
