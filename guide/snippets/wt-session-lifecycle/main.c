#define WIRED_MAIN
#include "wired.h"

/* App state kept per session, keyed on the session pointer. */
typedef struct {
  wired_wt_session* s; /* 0 = free slot */
  int               datagrams;
} session_state;

static session_state states[4];

static session_state* find(wired_wt_session* s) {
  for (usz i = 0; i < sizeof states / sizeof states[0]; i++)
    if (states[i].s == s) return &states[i];
  return 0;
}

/* Claim a free slot for the new session, starting from zeroed state. */
static void on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol) {
  (void)ctx;
  (void)path;
  (void)protocol;
  session_state* st = find(0);
  if (!st) return;
  *st = (session_state){.s = s};
  wired_log_str("session open\n");
}

/* First datagram: ask the client to wind down. The session stays open, so
 * the second datagram still arrives; then close with a code and a reason. */
static void on_datagram(void* ctx, wired_wt_session* s, wired_span data) {
  (void)ctx;
  (void)data;
  session_state* st = find(s);
  if (!st) return;
  if (++st->datagrams == 1) {
    wired_server_wt_drain_session(s);
    wired_log_str("drain sent\n");
    return;
  }
  wired_server_wt_close_session(
      s, 4001, wired_span_of((const u8*)"demo done", 9));
  wired_log_str("close sent\n");
}

/* Fires once per session. Release the slot: the next session may get the
 * same pointer, and it must not inherit this one's state. */
static void on_session_close(void* ctx, wired_wt_session* s) {
  (void)ctx;
  session_state* st = find(s);
  if (st) st->s = 0;
  wired_log_str("session closed, state released\n");
}

int wired_main(int argc, char** argv) {
  /* The same fixed demo identity as the HTTP/3 hello page. */
  static u8       priv[32], pub[32], seed[32], rnd[32];
  static const u8 scid[] = "guide-wt";
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x50 + i);
    seed[i] = (u8)(0x90 + i);
    rnd[i]  = (u8)(0xb0 + i);
  }
  wired_x25519_base(pub, priv);
  wired_srvboot_id id = {
      .priv                    = priv,
      .pub                     = pub,
      .cert_seed               = seed,
      .random                  = rnd,
      .scid                    = scid,
      .scid_len                = sizeof scid - 1, /* without the NUL */
      .max_datagram_frame_size = 65535, /* WebTransport requires DATAGRAM */
  };

  wired_srvrun_opt opt = {
      .incoming_cpu        = -1,
      .wt_on_session       = on_session,
      .wt_on_datagram      = on_datagram,
      .wt_on_session_close = on_session_close,
  };

  u16 port                 = (u16)wired_cliargs_int(argc, argv, "--port", 4433);
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  return wired_server_run_opt(port, &id, h, obs, &opt) ? 0 : 1;
}
