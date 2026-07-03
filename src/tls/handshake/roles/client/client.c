#include "tls/handshake/roles/client/client.h"

#include "common/platform/clock/clock.h"
#include "common/platform/rng/rng.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/io/socket/io/addr.h"
#include "transport/packet/build/pktbuild/initpad.h"

#define QUIC_CLIENT_CRYPTO_FRAME 256

/* Wall clock (fail-closed: a dead clock must not skip the validity check)
 * and the ECDHE private scalar. */
static int client_setup(quic_client *c) {
  c->now = quic_clock_ymdhms();
  if (c->now == 0) return 0;
  return quic_rng_bytes(c->my_priv, QUIC_ECDHE_LEN);
}

/* RFC 9000 7: generate our X25519 key pair and seed the handshake drivers. */
int quic_client_init(quic_client *c, const quic_client_init_in *in) {
  c->host     = in->server_name.p;
  c->host_len = in->server_name.n;
  c->castore  = 0;
  if (!client_setup(c)) return 0;
  quic_x25519_base(c->my_pub, c->my_priv);
  c->fd = wired_udp_socket();
  if (c->fd < 0) return 0;
  wired_udp_addr(&c->peer, in->port, in->server_ip);
  quic_tlsdriver_init(&c->tls, c->my_priv, c->my_pub, 0);
  quic_tlsdriver_set_sni(&c->tls, in->server_name.p, in->server_name.n);
  c->phase  = QUIC_CLIENT_HS_INITIAL;
  c->sh_len = 0;
  return 1;
}

void quic_client_set_now(quic_client *c, u64 now) { c->now = now; }

void quic_client_set_castore(quic_client *c, const quic_castore *store) {
  c->castore = store;
}

/* RFC 9000 14.1: ClientHello CRYPTO frame(s) padded to 1200.
 * ponytail: carries the ClientHello as a CRYPTO-frame payload, not yet an
 * AEAD-protected Initial; route through connio (Initial keys from the DCID)
 * when real on-wire protection is wired. The padded length is the on-wire one.
 */
usz quic_client_build_initial(quic_client *c, u8 *out, usz cap) {
  u8        ch[QUIC_CLIENT_HELLO_MAX];
  quic_obuf ob = quic_obuf_of(ch, sizeof(ch));
  if (!quic_tlsdriver_client_hello(&c->tls, &ob)) return 0;
  {
    quic_crypto_stream_emit_in ein = {0, QUIC_CLIENT_CRYPTO_FRAME};
    quic_obuf                  fb  = quic_obuf_of(out, cap);
    if (!quic_crypto_stream_emit(quic_span_of(ch, ob.len), &ein, &fb)) return 0;
    return quic_pktbuild_init_pad(out, fb.len, cap);
  }
}

int quic_client_start(quic_client *c) {
  u8  dg[QUIC_CLIENT_DATAGRAM_MAX];
  usz len = quic_client_build_initial(c, dg, sizeof(dg));
  if (len == 0) return 0;
  return wired_udp_send(c->fd, &c->peer, quic_span_of(dg, len)) == (i64)len;
}

/* RFC 8446 4.4.3: CertificateVerify body opens with the 2-byte scheme. */
static u16 cv_scheme(const u8 *msg) {
  return (u16)((msg[QUIC_HS_HEADER] << 8) | msg[QUIC_HS_HEADER + 1]);
}

/* RFC 8446 4.4: hand one fullhs-phase message to its entry point by type. */
static int dispatch_cert(quic_client *c, const u8 *m, usz n) {
  return quic_fullhs_recv_cert(&c->hs, m, n);
}
static int dispatch_cv(quic_client *c, const u8 *m, usz n) {
  return quic_fullhs_recv_certverify(&c->hs, quic_span_of(m, n), cv_scheme(m));
}
static int dispatch_fin(quic_client *c, const u8 *m, usz n) {
  return quic_fullhs_recv_finished(&c->hs, m, n);
}

static const struct {
  u8 type;
  int (*fn)(quic_client *, const u8 *, usz);
} feed_table[] = {
    {QUIC_HSD_CERTIFICATE, dispatch_cert},
    {QUIC_HSD_CERT_VERIFY, dispatch_cv},
    {QUIC_HS_FINISHED, dispatch_fin},
};

static int feed_auth_msg(quic_client *c, const u8 *msg, usz len) {
  u8 t = quic_hs_message_type(msg);
  for (usz i = 0; i < sizeof(feed_table) / sizeof(feed_table[0]); i++)
    if (feed_table[i].type == t) return feed_table[i].fn(c, msg, len);
  return 0;
}

/* RFC 9001 4.1: derive the 1-RTT keys and confirm a completed handshake. */
static int do_confirm(quic_client *c) {
  int ok = quic_fullhs_advance_application(&c->hs);
  return ok && quic_fullhs_confirmed(&c->hs);
}

static int feed_confirm(quic_client *c) {
  if (!quic_fullhs_is_complete(&c->hs)) return 1; /* flight still in progress */
  if (!do_confirm(c)) return 0;
  c->phase = QUIC_CLIENT_HS_CONFIRMED;
  return 1;
}

/* RFC 8446 4: drive the fullhs flight, then try to confirm. */
static int client_feed_auth(quic_client *c, const u8 *msg, usz len) {
  if (!feed_auth_msg(c, msg, len)) return 0;
  return feed_confirm(c);
}

/* Save the ServerHello bytes as the transcript fullhs is seeded from. */
static void save_sh(quic_client *c, const u8 *msg, usz len) {
  c->sh_len = len < sizeof(c->sh_transcript) ? len : sizeof(c->sh_transcript);
  for (usz i = 0; i < c->sh_len; i++) c->sh_transcript[i] = msg[i];
}

/* RFC 9001 4.1: ServerHello fixes the ECDHE secret; seed fullhs from it. The
 * cert acceptance policy (validity window + SAN) is injected here so a
 * quic_client always enforces it — there is no call for the app to forget. */
static int feed_initial(quic_client *c, const u8 *msg, usz len) {
  if (!quic_tlsdriver_recv_crypto(&c->tls, msg, len)) return 0;
  save_sh(c, msg, len);
  if (!quic_fullhs_init(
          &c->hs, &c->tls, quic_span_of(c->sh_transcript, c->sh_len)))
    return 0;
  quic_fullhs_set_policy(&c->hs, c->now, quic_span_of(c->host, c->host_len));
  quic_fullhs_set_castore(&c->hs, c->castore);
  c->phase = QUIC_CLIENT_HS_AUTH;
  return 1;
}

int quic_client_feed(quic_client *c, const u8 *crypto_payload, usz len) {
  if (c->phase == QUIC_CLIENT_HS_INITIAL)
    return feed_initial(c, crypto_payload, len);
  if (c->phase == QUIC_CLIENT_HS_AUTH)
    return client_feed_auth(c, crypto_payload, len);
  return 0;
}

int quic_client_pump(quic_client *c) {
  u8  dg[QUIC_CLIENT_DATAGRAM_MAX];
  i64 n = wired_udp_recv(c->fd, quic_mspan_of(dg, sizeof(dg)));
  if (n <= 0) return 0;
  return quic_client_feed(c, dg, (usz)n);
}

int quic_client_run_handshake(quic_client *c, int max_iterations) {
  for (int i = 0; i < max_iterations && !quic_client_is_connected(c); i++)
    quic_client_pump(c);
  return quic_client_is_connected(c);
}

int quic_client_is_connected(const quic_client *c) {
  return c->phase == QUIC_CLIENT_HS_CONFIRMED;
}

void quic_client_close(quic_client *c) {
  if (c->fd >= 0) syscall1(SYS_close, c->fd);
  c->fd = -1;
}
