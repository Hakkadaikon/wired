#define WIRED_MAIN
#include "wired.h"

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
  (void)more;
  (void)total_size;
  wired_log_str("request /\n");
  *content_type = "text/plain";
  memcpy(body_out->p, "ok", 2);
  body_out->len = 2;
  return 1;
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-h3";
  wired_srvboot_id id = {0};
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  id.priv      = priv;
  id.pub       = pub;
  id.cert_seed = seed;
  id.random    = rnd;
  id.scid      = scid;
  id.scid_len  = sizeof scid - 1; /* without the string's NUL */
  /* Non-0 enables session-ticket resumption/0-RTT (RFC 8446 4.6.1): the
   * SDK's fixed per-process ticket key, shared with the id this server
   * uses to OPEN a presented ticket (ticket_seal/ticket_open are
   * symmetric). */
  id.ticket_key = wired_srvloop_ticket_key();

  wired_srvrun_opt opt = {0};
  opt.incoming_cpu      = -1;
  /* RFC 9000 8.1.2: answer every Initial with a stateless Retry first,
   * only accepting one that carries a valid Retry token. */
  opt.force_retry       = 1;

  wired_srvrun_obs obs = {
      "demo.qlog",   /* RFC 9002-shaped packet_sent/packet_received events */
      "demo.keylog", /* SSLKEYLOGFILE, decrypts a capture in Wireshark */
      0,
      0,
      1, /* CC_ALGO_CUBIC (see transport/recovery/congestion/cc/cc.h);
          * 0 = NewReno, 2 = BBR */
  };

  u16                  port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h    = {.cb = on_request};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
