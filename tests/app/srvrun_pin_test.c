#include "common/bytes/util/be.h"
#include "test.h"
#include "tls/handshake/core/tls/retry_tag.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/poll/wait.h"
#include "transport/packet/build/initpkt/initpkt.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/version/version/version.h"

/* RFC 9000 21.1.1.2 / ACK-frequency draft 10-2: force_retry lets the server
 * demand a cheap Retry round-trip from every new client before it commits
 * to expensive handshake work, closing pre-handshake resource exhaustion
 * (and the same peer-DoS mitigation applies to ACK_FREQUENCY/IMMEDIATE_ACK
 * processing cost). Pins srvrun_retry_applies (same TU as srvrun.c: this
 * file is included into tests/run.c after srvrun.c, per the unity build). */

static wired_srvboot_id sr_pin_id(void) {
  wired_srvboot_id id = {0};
  id.scid_len         = 8;
  return id;
}

static srvrun_cfg sr_pin_cfg(wired_srvboot_id* id, int force_retry) {
  srvrun_cfg cfg  = {0};
  cfg.fd          = -1;
  cfg.id          = id;
  cfg.force_retry = force_retry;
  cfg.env         = &g_srvrun_env;
  return cfg;
}

/* A minimal long-header Initial: byte0 has the long-header bit set and wears
 * PT_INITIAL for QUIC v1 (version 0x00000001), followed by a DCID length
 * byte and that many DCID bytes -- exactly what wired_srvboot_is_initial and
 * srvrun_retry_wanted/applies read. */
static usz sr_pin_build_initial(u8* out) {
  out[0] = 0xC0; /* long header, PT_INITIAL bits for v1 */
  out[1] = 0x00, out[2] = 0x00, out[3] = 0x00, out[4] = 0x01; /* version 1 */
  out[5] = 4;                                                 /* dcid_len */
  out[6] = out[7] = out[8] = out[9] = 0xAB;                   /* dcid bytes */
  return 10;
}

static srvrun_step_ctx sr_pin_ctx(const srvrun_cfg* cfg, srvrun_state* st) {
  srvrun_step_ctx ctx = {0};
  ctx.cfg             = cfg;
  ctx.st              = st;
  return ctx;
}

/* force_retry=1 and a fresh Initial with a DCID matching no live/pending
 * slot: the gate applies (demands a Retry before any handshake work). */
static void test_srvrun_force_retry_applies_when_on(void) {
  wired_srvboot_id id  = sr_pin_id();
  srvrun_cfg       cfg = sr_pin_cfg(&id, 1);
  conntable        table[WIRED_CONNTABLE_CAP];
  conntable_init(table, WIRED_CONNTABLE_CAP);
  srvrun_conn conns[WIRED_CONNTABLE_CAP];
  bytes_memset(conns, 0, sizeof conns);
  srvrun_state    st  = {table, conns};
  srvrun_step_ctx ctx = sr_pin_ctx(&cfg, &st);

  u8  dg[16];
  usz n = sr_pin_build_initial(dg);
  CHECK(
      srvrun_retry_applies(
          &ctx, wired_span_of(dg + 6, 4), wired_mspan_of(dg, n)) == 1);
}

/* force_retry=0: the gate never applies, regardless of the datagram. */
static void test_srvrun_force_retry_off_never_applies(void) {
  wired_srvboot_id id  = sr_pin_id();
  srvrun_cfg       cfg = sr_pin_cfg(&id, 0);
  conntable        table[WIRED_CONNTABLE_CAP];
  conntable_init(table, WIRED_CONNTABLE_CAP);
  srvrun_conn conns[WIRED_CONNTABLE_CAP];
  bytes_memset(conns, 0, sizeof conns);
  srvrun_state    st  = {table, conns};
  srvrun_step_ctx ctx = sr_pin_ctx(&cfg, &st);

  u8  dg[16];
  usz n = sr_pin_build_initial(dg);
  CHECK(
      srvrun_retry_applies(
          &ctx, wired_span_of(dg + 6, 4), wired_mspan_of(dg, n)) == 0);
}

/* A DCID that already routes to a live slot is not gated again: the gate
 * only targets a fresh, unrecognized Initial. */
static void test_srvrun_force_retry_skips_known_slot(void) {
  wired_srvboot_id id  = sr_pin_id();
  srvrun_cfg       cfg = sr_pin_cfg(&id, 1);
  conntable        table[WIRED_CONNTABLE_CAP];
  conntable_init(table, WIRED_CONNTABLE_CAP);
  srvrun_conn conns[WIRED_CONNTABLE_CAP];
  bytes_memset(conns, 0, sizeof conns);

  u8  dg[16];
  usz n = sr_pin_build_initial(dg);
  CHECK(conntable_insert(table, WIRED_CONNTABLE_CAP, dg + 6, 4) >= 0);

  srvrun_state    st  = {table, conns};
  srvrun_step_ctx ctx = sr_pin_ctx(&cfg, &st);
  CHECK(
      srvrun_retry_applies(
          &ctx, wired_span_of(dg + 6, 4), wired_mspan_of(dg, n)) == 0);
}

/* Serve one tokenless client Initial of `version` through srvrun_serve with
 * force_retry on, and return the Retry the server sent to the client
 * socket (bytes into pkt, 0 if none arrived). */
static usz sr_pin_retry_for(u32 version, u8* pkt, usz cap) {
  static const u8  odcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  static const u8  cscid[4] = {0xc1, 0xc2, 0xc3, 0xc4};
  static const u8  crypto[] = {1, 2, 3, 4};
  wired_srvboot_id id       = sr_pin_id();
  srvrun_cfg       cfg      = sr_pin_cfg(&id, 1);
  conntable        table[WIRED_CONNTABLE_CAP];
  srvrun_state     st = {table, g_srvrun_state.conns};
  sockaddr         srv, cli, from;
  u8               dg[1300];
  wired_obuf       o = obuf_of(dg, sizeof dg);
  initpkt_desc     d = {
      wired_span_of(odcid, 8), wired_span_of(cscid, 4),
      wired_span_of(crypto, 4), 0, 0};
  i64 sfd = wired_udp_socket(), cfd = wired_udp_socket(), r = 0;
  wired_udp_addr(&srv, 47613, (const u8[4]){127, 0, 0, 1});
  wired_udp_addr(&cli, 47614, (const u8[4]){127, 0, 0, 1});
  CHECK(wired_udp_bind(sfd, &srv) >= 0);
  CHECK(wired_udp_bind(cfd, &cli) >= 0);
  CHECK(initpkt_build_ver(version, &d, &o));
  bytes_memset(st.conns, 0, sizeof g_srvrun_state.conns);
  cfg.fd = sfd;
  conntable_init(table, WIRED_CONNTABLE_CAP);
  {
    srvrun_step_ctx ctx = {&cfg, &cli, &st, 0, 0};
    srvrun_serve(&ctx, wired_mspan_of(dg, o.len));
  }
  if (poll_wait_readable(cfd, 100) > 0) {
    r = wired_udp_recvfrom(cfd, wired_mspan_of(pkt, cap), &from);
  }
  wired_udp_close(sfd);
  wired_udp_close(cfd);
  CHECK(st.conns[0].up == 0); /* stateless: no slot was claimed */
  return r > 0 ? (usz)r : 0;
}

/* RFC 9369 4.1: a Retry answers in the original version -- the client
 * Initial's own. A v2 Initial gets a v2 Retry (Version field, v2 Retry type
 * bits, RFC 9369 3.3.3 integrity key); a v1 Initial still gets a v1 one.
 * Both tags verify against the Initial's DCID (RFC 9001 5.8 ODCID). */
static void test_srvrun_force_retry_uses_initial_version(void) {
  static const u8 odcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  u8              pkt[256];
  usz             n = sr_pin_retry_for(VERSION_2, pkt, sizeof pkt);
  CHECK(n > 5 + 16);
  CHECK(be_get_be32(pkt + 1) == VERSION_2);
  CHECK(packet_long_type(pkt[0], VERSION_2) == PT_RETRY);
  CHECK(retry_verify_ver(
      VERSION_2, wired_span_of(odcid, 8), wired_span_of(pkt, n)));
  n = sr_pin_retry_for(VERSION_1, pkt, sizeof pkt);
  CHECK(n > 5 + 16);
  CHECK(be_get_be32(pkt + 1) == VERSION_1);
  CHECK(packet_long_type(pkt[0], VERSION_1) == PT_RETRY);
  CHECK(retry_verify(wired_span_of(odcid, 8), wired_span_of(pkt, n)));
}

/* Pinning: RFC 9114 10.5.2 -- unlike TCP's kernel TIME_WAIT, this SDK has no
 * lingering-slot-retention analog after a connection/CONNECT stream closes:
 * srvrun_free_slot immediately clears `up`, removes the conntable entry, and
 * zeroes the boot-accounting fields, so the very same slot is available to
 * a brand-new client's Initial right away (V-0452). */
static void test_srvrun_connect_slot_freed_after_close(void) {
  wired_srvboot_id id  = sr_pin_id();
  srvrun_cfg       cfg = sr_pin_cfg(&id, 0);
  conntable        table[WIRED_CONNTABLE_CAP];
  conntable_init(table, WIRED_CONNTABLE_CAP);
  srvrun_conn conns[WIRED_CONNTABLE_CAP];
  bytes_memset(conns, 0, sizeof conns);
  srvrun_state st = {table, conns};

  u8  dcid[4] = {0xAB, 0xAB, 0xAB, 0xAB};
  int slot    = conntable_insert(table, WIRED_CONNTABLE_CAP, dcid, 4);
  CHECK(slot >= 0);
  /* a raw {0} wipe leaves bigbuf_row at 0 (a valid-looking claimed row);
   * srvrun_open_slot always sets -1 on a real accept, mirrored here so
   * srvrun_free_bigbuf_rows sees the same "never claimed" state it would
   * on a real slot. */
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    conns[slot].resp[i].bigbuf_row = -1;
  }
  conns[slot].up              = 1;
  conns[slot].boot_rx_bytes   = 999;
  conns[slot].boot_tx_bytes   = 999;
  conns[slot].boot_dgram_sent = 5;
  conns[slot].boot_ini_len    = 123;

  srvrun_free_slot(&cfg, &st, slot);

  CHECK(conns[slot].up == 0);
  CHECK(conns[slot].boot_rx_bytes == 0);
  CHECK(conns[slot].boot_tx_bytes == 0);
  CHECK(conns[slot].boot_dgram_sent == 0);
  CHECK(conns[slot].boot_ini_len == 0);
  /* the freed slot's CID no longer routes -- and the table can immediately
   * claim a brand-new client into the very same physical slot. */
  CHECK(conntable_find(table, WIRED_CONNTABLE_CAP, dcid, 4) == -1);
  u8  new_dcid[4] = {0xCD, 0xCD, 0xCD, 0xCD};
  int slot2       = conntable_insert(table, WIRED_CONNTABLE_CAP, new_dcid, 4);
  CHECK(slot2 == slot);
}

/* Retry-token key rotation (keyring.h): a token minted under the current or
 * previous epoch's key verifies; one two epochs old does not. */
static int sr_pin_token_gen_ok(u64 back) {
  sockaddr        peer = {0};
  srvrun_step_ctx ctx  = {0};
  u8              key[KEYRING_KEY], odcid[4] = {1, 2, 3, 4};
  u8              tok[RETRYTOKEN_WIRE_MAX];
  wired_span      got;
  usz             n;
  ctx.peer = &peer;
  keyring_key(srvkeys_retry(), wired_clock_epoch_secs(), back, key);
  n = retrytoken_wire_make(
      key, wired_span_of((const u8*)&peer, sizeof peer),
      wired_span_of(odcid, 4), tok);
  return srvrun_retry_token_ok(&ctx, wired_span_of(tok, n), &got);
}

static void test_srvrun_retry_token_rotation(void) {
  CHECK(sr_pin_token_gen_ok(0) == 1);
  CHECK(sr_pin_token_gen_ok(1) == 1);
  CHECK(sr_pin_token_gen_ok(2) == 0);
}

void test_srvrun_pin(void) {
  test_srvrun_retry_token_rotation();
  test_srvrun_force_retry_applies_when_on();
  test_srvrun_force_retry_off_never_applies();
  test_srvrun_force_retry_skips_known_slot();
  test_srvrun_force_retry_uses_initial_version();
  test_srvrun_connect_slot_freed_after_close();
}
