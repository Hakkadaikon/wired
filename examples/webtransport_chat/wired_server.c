/* Real-UDP HTTP/3 + WebTransport chat server. libc-free, x86_64-linux, direct
 * syscalls, driven by the single SDK header <wired.h>.
 *
 * The chat logic is one line: every received WebTransport DATAGRAM is fanned
 * out, unmodified, to every active WT session via wired_server_broadcast_
 * datagram (srvrun.h). Driver selection (plain/workers/AF_XDP/threads) and
 * its CLI parsing are delegated wholesale to app/http3/server/srvdriver. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

#include "app/http3/server/srvdriver/srvdriver.h"
#include "common/platform/clock/clock.h"
#include "common/platform/exit/exit.h"

/* --- WebTransport chat: fan received datagrams out to every session ------ */

/* draft-ietf-webtrans-http3-15 SS4: relay one received DATAGRAM to every
 * active WebTransport session, byte-for-byte, no interpretation. */
static void wt_on_datagram_cb(
    void* app_ctx, wired_wt_session* s, quic_span data) {
  (void)app_ctx;
  (void)s;
  wired_server_broadcast_datagram(data);
}

/* --- Plain HTTP/3 app: identical shape to examples/webtransport_echo ----- */

/* A GET to any path answers 200 with a short description of this demo. */
static int app_on_request(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                content_type) {
  static const u8 body[] =
      "webtransport_chat: connect via WebTransport and send DATAGRAMs.\n"
      "Every received datagram is broadcast, unmodified, to every other\n"
      "active WebTransport session on this server.\n";
  usz i;
  (void)ctx;
  (void)req;
  *content_type = "text/plain";
  for (i = 0; i < sizeof body - 1 && i < body_out->cap; i++)
    body_out->p[i] = body[i];
  body_out->len = i;
  return 1;
}

/* Fixed, deterministic server identity for wired_server_run_opt (same recipe
 * as webtransport_echo/word_list: a demo needs no key rotation). */
static const u8 SERVER_SCID[6] = {'W', 'T', 'C', 'H', 'A', 'T'};

typedef struct {
  u8 priv[32];
  u8 pub[32];
  u8 seed[32];
  u8 rnd[32];
  u8 san_ipv4[4];
} server_keys;

static void server_identity(
    wired_srvboot_id* id, server_keys* k, int have_san_ipv4, u64 now_secs) {
  for (usz i = 0; i < 32; i++) {
    k->priv[i] = (u8)(0x50 + i);
    k->seed[i] = (u8)(0x90 + i);
    k->rnd[i]  = (u8)(0xb0 + i);
  }
  quic_x25519_base(k->pub, k->priv);
  id->priv                    = k->priv;
  id->pub                     = k->pub;
  id->cert_seed               = k->seed;
  id->scid                    = SERVER_SCID;
  id->scid_len                = sizeof SERVER_SCID;
  id->random                  = k->rnd;
  id->chain                   = 0; /* self-signed */
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535; /* required for DATAGRAM delivery */
  id->san_ipv4                = have_san_ipv4 ? k->san_ipv4 : 0;
  id->now_secs                = now_secs;
}

/* --san-ipv4 a.b.c.d: RFC 5280 4.2.1.6 SAN entry a browser checks when
 * connecting to a bare IP literal (the default self-signed cert otherwise
 * carries only dNSName=localhost). */
static void load_san_ipv4(int argc, char** argv, u8 san_ipv4[4], int* have_it) {
  const char* ip_str = wired_cliargs_str(argc, argv, "--san-ipv4", 0);
  *have_it            = ip_str != 0;
  if (ip_str && !wired_cliargs_ipv4(ip_str, san_ipv4))
    wired_die("--san-ipv4: expected dotted-quad a.b.c.d\n");
}

__attribute__((force_align_arg_pointer, used)) int wired_main(
    int argc, char** argv) {
  wired_srvboot_id     id;
  server_keys          keys;
  wired_srvdriver_opt  opt;
  int                  have_san_ipv4;
  u16 port = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  u64 now_secs = quic_clock_epoch_secs();
  wired_srvrun_handler h   = {app_on_request, 0};
  wired_srvrun_obs     obs = {
      wired_cliargs_str(argc, argv, "--qlog", 0),
      wired_cliargs_str(argc, argv, "--keylog", 0), 0, 0, 0};

  load_san_ipv4(argc, argv, keys.san_ipv4, &have_san_ipv4);
  server_identity(&id, &keys, have_san_ipv4, now_secs);

  if (!wired_srvdriver_parse(argc, argv, &opt))
    wired_die(
        "bad CLI flags (check --workers/--cores/--ifindex/--pin-core "
        "combinations)\n");
  opt.run.incoming_cpu   = -1;
  opt.run.wt_on_datagram = wt_on_datagram_cb;

  if (!wired_srvdriver_run(port, &id, h, obs, &opt))
    wired_die("listen failed\n");
  return 0;
}
