#define WIRED_MAIN
#include "wired.h"

/* The first byte of a received datagram picks which of srvrun.h's three
 * datagram-fanout primitives relays the rest: 1 = the single-slot
 * wired_server_broadcast_datagram (a second broadcast in the same loop
 * step overwrites the first); 2 = wired_server_broadcast_datagram_ring,
 * the bounded ring that queues several without overwriting; 3 =
 * wired_server_wt_send_datagram_to, addressed back at the sender only --
 * not a broadcast at all. */
static void on_datagram(void* ctx, wired_wt_session* s, wired_span data) {
  (void)ctx;
  if (data.n == 0) return;
  wired_span rest = wired_span_of(data.p + 1, data.n - 1);
  switch (data.p[0]) {
    case 1:
      wired_server_broadcast_datagram(rest);
      break;
    case 2:
      wired_server_broadcast_datagram_ring(rest);
      break;
    case 3:
      wired_server_wt_send_datagram_to(s, rest);
      break;
  }
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
  id.cert_seed               = seed;
  id.random                  = rnd;
  id.scid                    = scid;
  id.scid_len                = sizeof scid - 1; /* without the string's NUL */
  id.max_datagram_frame_size = 65535; /* WebTransport requires DATAGRAM */

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu      = -1;
  opt.wt_on_datagram    = on_datagram;

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {0};
  wired_srvrun_obs     obs  = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
