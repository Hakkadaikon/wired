#define WIRED_MAIN
#include "wired.h"

static int span_is(wired_span s, const char* lit) {
  usz n = 0;
  while (lit[n]) n++;
  if (s.n != n) return 0;
  for (usz i = 0; i < n; i++)
    if (s.p[i] != (u8)lit[i]) return 0;
  return 1;
}

/* draft-ietf-webtrans-http3-15 SS3.1 / RFC 6454: an explicit allow-list.
 * A CONNECT with no Origin header at all arrives here as an empty span --
 * the SDK itself (srvrun.c's wt_origin_ok) already answers 403 for a
 * present-but-empty Origin header before this callback ever runs, so an
 * empty span here always means "absent", never "present but empty". */
static int allowed_origin(void* ctx, wired_span origin, wired_span authority) {
  (void)ctx;
  (void)authority;
  return span_is(origin, "https://ok.example");
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-wo";
  wired_srvboot_id id = {0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  id.priv                    = priv;
  id.pub                     = pub;
  id.cert_seed               = seed;
  id.random                  = rnd;
  id.scid                    = scid;
  id.scid_len                = sizeof scid - 1; /* without the string's NUL */
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  wired_srvrun_opt opt  = {0};
  opt.incoming_cpu      = -1;
  opt.wt_protocols      = "chat";
  opt.wt_origin_check   = allowed_origin;

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
