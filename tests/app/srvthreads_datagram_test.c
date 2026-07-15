#include "app/datagram/datagram/datagram.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/request/h3reqenc/pseudo_encode.h"
#include "app/http3/server/srvrun/srvrun.h"
#include "app/http3/server/srvthreads/srvthreads.h"
#include "app/webtransport/session/session/session.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/debug/debug.h"
#include "common/platform/thread/thread.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "test.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/client/client.h"
#include "tls/handshake/roles/client/clientwire.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/stream/data/appdata/app_send.h"

/* @file
 * Reproduces (or disproves) the reported bug: with `wired_srvthreads_run`
 * fanning out a single worker (--cores 0, plain UDP + SO_REUSEPORT mode), a
 * WebTransport DATAGRAM broadcast from the SDK's own wired_server_broadcast_
 * datagram never reaches even the sender itself, though the identical single-
 * process wired_server_run_opt path works.
 *
 * This drives a genuinely independent client role (quic_client + clientwire's
 * real-AEAD codec + quic_fullhs, none of which peek into wired_server/
 * wired_srvloop internals) over a real 127.0.0.1 UDP socket against a real
 * wired_srvthreads_run(...) worker thread, so the reproduction exercises the
 * exact code path a browser would: Initial -> ServerHello -> Handshake
 * Finished -> 1-RTT confirm -> Extended CONNECT (WebTransport) -> DATAGRAM
 * send -> DATAGRAM echo receive.
 *
 * Each stage has its own CHECK so a failure pinpoints handshake vs. WT
 * session establishment vs. datagram echo. */

static const u8 g_sdt_cli_scid[6] = {'C', 'L', 'I', 'S', 'C', 'I'};
static const u8 g_sdt_srv_scid[6] = {'S', 'R', 'V', 'S', 'C', 'I'};

#define SDT_PORT 14961

/* SO_RCVTIMEO (Linux SOL_SOCKET=1, SO_RCVTIMEO=20): bound every recv on the
 * client socket so a reproduction of "the reply never comes" fails fast
 * instead of hanging the whole suite. quic_timespec/struct timeval share the
 * same {sec, usec-or-nsec} layout for this purpose; SO_RCVTIMEO wants
 * {tv_sec, tv_usec}. */
typedef struct {
  i64 tv_sec;
  i64 tv_usec;
} sdt_timeval;

static void sdt_set_rcvtimeo(i64 fd, i64 ms) {
  sdt_timeval tv = {ms / 1000, (ms % 1000) * 1000};
  syscall6(
      SYS_setsockopt, fd, 1 /* SOL_SOCKET */, 20 /* SO_RCVTIMEO */, (i64)&tv,
      sizeof(tv), 0);
}

/* --- server identity (self-signed, DATAGRAM-enabled) ---------------------
 */

static void sdt_make_id(
    wired_srvboot_id* id, u8 priv[32], u8 pub[32], u8 seed[32], u8 rnd[32]) {
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x60 + i);
    seed[i] = (u8)(0xa0 + i);
    rnd[i]  = (u8)(0xc0 + i);
  }
  quic_x25519_base(pub, priv);
  id->priv                    = priv;
  id->pub                     = pub;
  id->cert_seed               = seed;
  id->scid                    = g_sdt_srv_scid;
  id->scid_len                = 6;
  id->random                  = rnd;
  id->chain                   = 0;
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 65535; /* DATAGRAM delivery, RFC 9221 3 */
  id->san_ipv4                = 0;
  id->now_secs                = 0;
}

/* draft-ietf-webtrans-http3-15 SS4: relay every received DATAGRAM to every
 * active WT session -- byte-identical to examples/webtransport_chat's
 * wt_on_datagram_cb, the exact callback the bug report exercises. */
static void sdt_on_datagram_cb(void* ctx, wired_wt_session* s, quic_span d) {
  (void)ctx;
  (void)s;
  wired_server_broadcast_datagram(d);
}

/* Thread entry point: run one srvthreads worker (n_cores=1, control_core=-1,
 * plain UDP + SO_REUSEPORT mode -- exactly `--cores 0`) until the shared
 * shutdown word is set. */
static void sdt_server_thread(void* argp) {
  wired_srvboot_id*    id  = (wired_srvboot_id*)argp;
  wired_srvthreads_opt opt = {0};
  opt.cores[0]             = 0;
  opt.n_cores              = 1;
  opt.control_core         = -1;
  opt.run.incoming_cpu     = -1;
  opt.run.wt_on_datagram   = sdt_on_datagram_cb;
  wired_srvrun_handler h   = {0, 0};
  wired_srvrun_obs     obs = {0, 0, 0, 0, 0};
  wired_srvthreads_run(SDT_PORT, id, h, obs, &opt);
}

/* --- independent client role: real AEAD wire, own key schedule -----------
 * Every seal/open below goes through quic_client's own c.tls.ks (derived
 * from OUR ECDHE exchange with the server, via quic_tlsdriver_recv_crypto /
 * quic_fullhs), never wired_server's. This is the "hard mode" the task asks
 * for: a peer that only ever sees the server's bytes on the wire. */

struct sdt_client {
  quic_client      c;
  i64              fd;
  quic_sockaddr_in srv;
  u8               priv[32], pub[32];
  u8  ch[512]; /* our own raw ClientHello, saved for the transcript */
  usz ch_len;
  u8  chsh[900]; /* CH||SH, growing to CH||SH||EE below */
  usz chsh_len;
};

/* RFC 9221 3: advertise max_datagram_frame_size in our own ClientHello's
 * transport parameters so the server's DATAGRAM sender (srvrun_send_pending_
 * datagram, gated on sdrv.peer_max_datagram_frame_size) is willing to send us
 * a broadcast echo. quic_tlsdriver_raw_client_hello hardcodes an empty TP
 * blob (client-role default, no in-tree caller needed one until this test),
 * so build the ClientHello directly via quic_tls_client_hello instead of
 * going through it, and hand-sync tlsdriver's own transcript_ch bookkeeping
 * (normally quic_tlsdriver_client_hello's job) to the same bytes. */
static usz sdt_build_ch_with_dg_tp(struct sdt_client* cx, u8* ch, usz cap) {
  u8        tp[32];
  quic_obuf tob = quic_obuf_of(tp, sizeof tp);
  usz tn = quic_tparam_put_int(&tob, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 65535);
  /* RFC 9000 18.2: the server's send-credit gates (srvrun_can_send_new) now
   * consult initial_max_data/initial_max_stream_data_bidi_local from this
   * ClientHello -- without them the server's WT-status 2xx response is
   * blocked from byte 0, unrelated to what this test actually exercises
   * (the DATAGRAM broadcast echo). Generously high so it never binds. */
  {
    quic_obuf tob2 = quic_obuf_of(tp + tn, sizeof tp - tn);
    tn += quic_tparam_put_int(&tob2, QUIC_TP_INITIAL_MAX_DATA, 1u << 24);
  }
  {
    quic_obuf tob3 = quic_obuf_of(tp + tn, sizeof tp - tn);
    tn += quic_tparam_put_int(
        &tob3, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 1u << 24);
  }
  static const u8     random[32] = {0};
  quic_clienthello_in in         = {
      random, cx->pub, quic_span_of((const u8*)0, 0), quic_span_of(tp, tn)};
  quic_obuf ob = quic_obuf_of(ch, cap);
  usz       n  = quic_tls_client_hello(&in, &ob);
  if (n == 0) return 0;
  quic_memcpy(cx->c.tls.transcript_ch, ch, n);
  cx->c.tls.transcript_ch_len = n;
  return n;
}

static void sdt_client_init(struct sdt_client* cx) {
  for (usz i = 0; i < 32; i++) cx->priv[i] = (u8)(0x11 + i);
  quic_x25519_base(cx->pub, cx->priv);
  quic_tlsdriver_init(&cx->c.tls, cx->priv, cx->pub, 0);
  /* Our own raw ClientHello (with the DATAGRAM transport parameter), saved
   * for the transcript -- reproduces byte-for-byte what sdt_do_initial sends
   * on the wire. */
  cx->ch_len = sdt_build_ch_with_dg_tp(cx, cx->ch, sizeof cx->ch);
  cx->fd     = wired_udp_socket();
  if (cx->fd >= 0) sdt_set_rcvtimeo(cx->fd, 200); /* 200ms per recv */
  wired_udp_addr(&cx->srv, SDT_PORT, (const u8[4]){127, 0, 0, 1});
}

/* Send our real protected Initial (ClientHello) and return 1 once something
 * came back within a bounded number of retries (UDP is unreliable and the
 * worker thread's bind may not have completed the instant the thread
 * starts). ilen/hlen receive the two accept-flight datagram lengths
 * (Initial reply, then Handshake reply) once both arrive. */
/* One send-then-wait attempt: ship dg, and if an Initial reply comes back in
 * time, also wait for the Handshake reply that should immediately follow it
 * (the server's whole accept flight). Returns 1 only once both arrived. */
/* Wait for one reply datagram into buf; on arrival, records its length via
 * *out_len and returns 1. */
static int sdt_recv_one(i64 fd, u8* buf, usz cap, usz* out_len) {
  quic_sockaddr_in from;
  i64              r = wired_udp_recvfrom(fd, quic_mspan_of(buf, cap), &from);
  if (r <= 0) return 0;
  *out_len = (usz)r;
  return 1;
}

static int sdt_initial_attempt(
    struct sdt_client* cx,
    quic_span          dg,
    u8*                ini_reply,
    usz                cap,
    usz*               ilen,
    u8*                hs_reply,
    usz                hcap,
    usz*               hlen) {
  if (wired_udp_send(cx->fd, &cx->srv, dg) < 0) return 0;
  if (!sdt_recv_one(cx->fd, ini_reply, cap, ilen)) return 0;
  return sdt_recv_one(cx->fd, hs_reply, hcap, hlen);
}

/* Send our real protected Initial (ClientHello) and return 1 once the
 * server's whole accept flight (Initial reply, then Handshake reply) came
 * back within a bounded number of retries (UDP is unreliable and the worker
 * thread's bind may not have completed the instant the thread starts). */
/* Retry sdt_initial_attempt up to 30 times over the already-built Initial
 * datagram dg. */
static int sdt_retry_initial(
    struct sdt_client* cx,
    quic_span          dg,
    u8*                ini_reply,
    usz                cap,
    usz*               ilen,
    u8*                hs_reply,
    usz                hcap,
    usz*               hlen) {
  for (int attempt = 0; attempt < 30; attempt++)
    if (sdt_initial_attempt(cx, dg, ini_reply, cap, ilen, hs_reply, hcap, hlen))
      return 1;
  return 0;
}

/* Seals cx->ch (already built by sdt_client_init, with the DATAGRAM transport
 * parameter) into a protected Initial packet -- quic_client_build_initial_
 * wire cannot be reused here since it always rebuilds the ClientHello itself
 * via quic_tlsdriver_raw_client_hello's hardcoded empty transport parameters
 * (see sdt_build_ch_with_dg_tp's doc). */
static int sdt_do_initial(
    struct sdt_client* cx,
    u8*                ini_reply,
    usz                cap,
    usz*               ilen,
    u8*                hs_reply,
    usz                hcap,
    usz*               hlen) {
  u8                dg[1500];
  quic_obuf         ob = quic_obuf_of(dg, sizeof dg);
  quic_initpkt_desc d  = {
      quic_span_of(g_sdt_cli_scid, 6), quic_span_of(g_sdt_cli_scid, 6),
      quic_span_of(cx->ch, cx->ch_len), 0, 0};
  if (!quic_initpkt_build(&d, &ob)) return 0;
  return sdt_retry_initial(
      cx, quic_span_of(dg, ob.len), ini_reply, cap, ilen, hs_reply, hcap, hlen);
}

/* Open the server's Initial reply (ServerHello) and feed it to our own
 * tlsdriver (recovers the peer key_share, agrees the ECDHE secret, advances
 * the hsdriver order machine -- all correct). Does NOT yet derive final
 * Handshake keys or seed quic_fullhs: both need the transcript extended with
 * EncryptedExtensions first (RFC 8446 4.4 -- see sdt_finish_hs_secrets),
 * which only arrives in the Handshake packet opened next.
 *
 * ponytail-adjacent finding, not a fix: quic_tlsdriver_recv_crypto (src/tls/
 * handshake/core/tlsdriver/tlsdriver.c) derives Handshake traffic keys using
 * ONLY the just-received message as the RFC 8446 7.1 Transcript-Hash input,
 * never folding in the ClientHello (or EncryptedExtensions). Every existing
 * unit test pairs two quic_tlsdriver instances that both make this same
 * substitution, so it cancels out and looks correct there; it only surfaces
 * against a real peer (like wired_server here) whose own transcript
 * genuinely folds in every prior message. sdt_finish_hs_secrets below
 * recomputes it correctly via the public quic_keysched_advance_handshake
 * entry point -- enough to get this reproduction past the handshake; fixing
 * tlsdriver.c itself is a separate, pre-existing SDK gap outside this task's
 * scope. */
/* quic_tlsdriver_recv_crypto wants a raw CRYPTO frame (it runs
 * quic_frame_get_crypto itself), but quic_client_open_initial_wire already
 * unwrapped one -- re-wrap the recovered ServerHello bytes into a synthetic
 * CRYPTO frame at offset 0 so the driver can reassemble+consume it, the same
 * encoder quic_client_build_initial uses on the send side. Also captures
 * CH||SH into cx->chsh for sdt_rederive_hs_keys below. */
/* Append tls onto cx->ch to build cx->chsh (CH||SH); cx->ch_len bytes of
 * ClientHello, then tls.n bytes of ServerHello. Returns 0 if it would
 * overflow. */
static int sdt_append_chsh(struct sdt_client* cx, quic_span tls) {
  usz        off = 0;
  quic_mspan buf = quic_mspan_of(cx->chsh, sizeof cx->chsh);
  if (!quic_put_bytes(buf, &off, quic_span_of(cx->ch, cx->ch_len))) return 0;
  if (!quic_put_bytes(buf, &off, tls)) return 0;
  cx->chsh_len = off;
  return 1;
}

static int sdt_feed_serverhello(struct sdt_client* cx, quic_span tls) {
  u8                         cframe[600];
  quic_obuf                  cb  = quic_obuf_of(cframe, sizeof cframe);
  quic_crypto_stream_emit_in ein = {0, (usz)tls.n};
  if (!sdt_append_chsh(cx, tls)) return 0;
  if (!quic_crypto_stream_emit(tls, &ein, &cb)) return 0;
  return quic_tlsdriver_recv_crypto(&cx->c.tls, cframe, cb.len);
}

/* RFC 8446 7.1: client_/server_handshake_traffic_secret only need
 * Transcript-Hash(ClientHello..ServerHello) -- EncryptedExtensions is not
 * part of this input, so the Handshake AEAD keys can (and must) be corrected
 * here, before the Handshake packet carrying EE is even opened.
 * quic_fullhs's own transcript (needing CH||SH||EE) is seeded separately,
 * once EE's bytes are available -- see sdt_finish_hs_secrets. */
static int sdt_rederive_hs_keys(struct sdt_client* cx) {
  const u8* shared;
  if (!quic_tlsdriver_shared_secret(&cx->c.tls, &shared)) return 0;
  quic_keysched_init(&cx->c.tls.ks); /* undo the wrong-transcript stage */
  return quic_keysched_advance_handshake(
      &cx->c.tls.ks, quic_span_of(shared, 32),
      quic_span_of(cx->chsh, cx->chsh_len));
}

static int sdt_open_initial(struct sdt_client* cx, u8* pkt, usz len) {
  quic_span               tls;
  quic_clientwire_open_in oin = {
      quic_span_of(g_sdt_cli_scid, 6), quic_mspan_of(pkt, len), 0};
  if (!quic_client_open_initial_wire(&oin, &tls)) return 0;
  if (!sdt_feed_serverhello(cx, tls)) return 0;
  return sdt_rederive_hs_keys(cx);
}

/* RFC 8446 4.4: EncryptedExtensions (msg type 8, the first message of the
 * Handshake flight) carries no cryptographic content quic_fullhs needs to
 * verify, but its bytes DO belong in the Certificate/CertificateVerify/
 * Finished transcript hash (RFC 8446 4.4.1's Transcript-Hash runs over every
 * handshake message in order, EE included) -- quic_fullhs_init's `sh` param
 * seeds exactly that running transcript (h->tr), so EE must be folded in
 * here, before Certificate.
 *
 * quic_fullhs_init also derives hs_traffic_peer/hs_traffic_self (RFC 8446
 * 7.1 client_/server_handshake_traffic_secret, used only for each side's
 * Finished verify_data) from that SAME `sh` span -- but per RFC 8446 7.1
 * those secrets are Transcript-Hash(ClientHello..ServerHello) alone, EE
 * excluded (confirmed against the real server: sdrv_flight.c's
 * derive_secret() computes s_hs_traffic from s->tr at the point right after
 * build_server_hello, strictly before emit_hs_flight/EE exist). So
 * quic_fullhs_init's internal seed_secrets ends up deriving
 * hs_traffic_peer/self from CH||SH||EE, which will never match the real
 * peer's CH||SH-only secret -- this is the same pre-existing transcript gap
 * as quic_tlsdriver_recv_crypto (see sdt_open_initial's doc), just one call
 * layer up, and not something a caller can route around via quic_fullhs's
 * public API (there is no separate "extend the transcript without touching
 * hs_traffic" entry point). Recomputing hs_traffic_peer/self directly here
 * and overwriting the two fields is the workaround: it reuses the exact RFC
 * 8446 7.1 formula (quic_tls_derive_secret, "c hs traffic"/"s hs traffic"
 * over CH||SH only) that quic_tls_handshake_keys already applies correctly
 * for the AEAD keys in sdt_open_initial. */
/* cx->c.sh_transcript <- SH||EE (the ServerHello bytes alone, out of
 * cx->chsh = CH||SH via cx->ch_len as the split point, then EE) -- NOT
 * CH||SH||EE: quic_fullhs_init's own seed_secrets (RFC 8446 7.1) prepends
 * tls->transcript_ch (our saved ClientHello) itself, so a caller-supplied
 * `sh` must start at ServerHello or the ClientHello ends up folded in twice.
 * Returns 0 if it would overflow. */
static int sdt_build_chshee(struct sdt_client* cx, const u8* ee, usz ee_len) {
  usz        off    = 0;
  usz        sh_len = cx->chsh_len - cx->ch_len;
  quic_mspan buf =
      quic_mspan_of(cx->c.sh_transcript, sizeof cx->c.sh_transcript);
  if (!quic_put_bytes(buf, &off, quic_span_of(cx->chsh + cx->ch_len, sh_len)))
    return 0;
  if (!quic_put_bytes(buf, &off, quic_span_of(ee, ee_len))) return 0;
  cx->c.sh_len = off;
  return 1;
}

/* Extend cx->c.sh_transcript to SH||EE and seed quic_fullhs from it. */
static int sdt_seed_fullhs(struct sdt_client* cx, const u8* ee, usz ee_len) {
  if (!sdt_build_chshee(cx, ee, ee_len)) return 0;
  return quic_fullhs_init(
      &cx->c.hs, &cx->c.tls, quic_span_of(cx->c.sh_transcript, cx->c.sh_len));
}

/* Recompute hs_traffic_peer/self per RFC 8446 7.1 (label + CH||SH only) and
 * overwrite quic_fullhs_init's CH||SH||EE-tainted versions -- see this
 * function group's file-level doc for why. */
static int sdt_rederive_finished_secrets(struct sdt_client* cx) {
  u8                    hs[QUIC_HKDF_PRK];
  const u8*             shared;
  quic_derive_secret_in peer_in, self_in;
  if (!quic_tlsdriver_shared_secret(&cx->c.tls, &shared)) return 0;
  quic_tls_handshake_secret(shared, hs);
  peer_in = (quic_derive_secret_in){
      hs, quic_span_of((const u8*)"s hs traffic", 12),
      quic_span_of(cx->chsh, cx->chsh_len)};
  self_in = (quic_derive_secret_in){
      hs, quic_span_of((const u8*)"c hs traffic", 12),
      quic_span_of(cx->chsh, cx->chsh_len)};
  quic_tls_derive_secret(&peer_in, cx->c.hs.hs_traffic_peer);
  quic_tls_derive_secret(&self_in, cx->c.hs.hs_traffic_self);
  return 1;
}

static int sdt_finish_hs_secrets(
    struct sdt_client* cx, const u8* ee, usz ee_len) {
  if (!sdt_seed_fullhs(cx, ee, ee_len)) return 0;
  return sdt_rederive_finished_secrets(cx);
}

/* Open the server's Handshake reply (Certificate/CertificateVerify/Finished,
 * all in one CRYPTO frame for this SDK's self-signed identity -- confirmed
 * by tests/app/h3_loopback_test.c's test_srvboot_accept, out.dgram_count==1)
 * and drive quic_fullhs through it message by message. */
static int sdt_feed_cert(struct sdt_client* cx, const u8* m, usz n) {
  return quic_fullhs_recv_cert(&cx->c.hs, m, n);
}
static int sdt_feed_certverify(struct sdt_client* cx, const u8* m, usz n) {
  u16 scheme = (u16)((m[QUIC_HS_HEADER] << 8) | m[QUIC_HS_HEADER + 1]);
  return quic_fullhs_recv_certverify(&cx->c.hs, quic_span_of(m, n), scheme);
}
static int sdt_feed_finished(struct sdt_client* cx, const u8* m, usz n) {
  return quic_fullhs_recv_finished(&cx->c.hs, m, n);
}

static const struct {
  u8 type;
  int (*fn)(struct sdt_client*, const u8*, usz);
} sdt_hs_feed_table[] = {
    {QUIC_HSD_CERTIFICATE, sdt_feed_cert},
    {QUIC_HSD_CERT_VERIFY, sdt_feed_certverify},
    {QUIC_HS_FINISHED, sdt_feed_finished},
};

static int sdt_feed_one_hs_msg(struct sdt_client* cx, const u8* m, usz n) {
  u8 t = m[0];
  for (usz i = 0; i < sizeof sdt_hs_feed_table / sizeof sdt_hs_feed_table[0];
       i++)
    if (sdt_hs_feed_table[i].type == t)
      return sdt_hs_feed_table[i].fn(cx, m, n);
  return 0;
}

/* RFC 8446 4: one TLS handshake message's total length (header + body) at
 * p[off..), or 0 if the length prefix overruns n. */
static usz sdt_hs_msg_total(const u8* p, usz off, usz n) {
  usz mlen, total;
  if (off + 4 > n) return 0;
  mlen  = ((usz)p[off + 1] << 16) | ((usz)p[off + 2] << 8) | p[off + 3];
  total = 4 + mlen;
  return off + total <= n ? total : 0;
}

/* The first message in this SDK's Handshake flight is always
 * EncryptedExtensions (RFC 8446 4.4, quic_sdrv_flight.c's emit_ee_cert); it
 * carries nothing quic_fullhs needs to verify, but its bytes must reach the
 * transcript before quic_fullhs_init runs (see sdt_finish_hs_secrets) -- so
 * it is consumed here, not dispatched through sdt_feed_one_hs_msg. Returns
 * the byte offset just past EE, or 0 on a malformed flight. */
/* total is a well-formed, in-bounds EncryptedExtensions message at p[0..). */
static int sdt_is_ee(const u8* p, usz total) {
  return total != 0 && p[0] == QUIC_HSD_ENCRYPTED_EXT;
}

static usz sdt_consume_ee(struct sdt_client* cx, const u8* p, usz n) {
  usz total = sdt_hs_msg_total(p, 0, n);
  if (!sdt_is_ee(p, total)) return 0;
  if (!sdt_finish_hs_secrets(cx, p, total)) return 0;
  return total;
}

/* One message step within sdt_feed_rest's walk: feeds the message at p[off..)
 * and returns the offset just past it, or 0 (== off's only valid "done"
 * value when off > 0) on a malformed/rejected message. */
static usz sdt_feed_rest_step(
    struct sdt_client* cx, const u8* p, usz off, usz n) {
  usz total = sdt_hs_msg_total(p, off, n);
  if (total == 0) return 0;
  if (!sdt_feed_one_hs_msg(cx, p + off, total)) return 0;
  return off + total;
}

/* Every message after EncryptedExtensions (Certificate, CertificateVerify,
 * Finished), fed to quic_fullhs in order. */
static int sdt_feed_rest(struct sdt_client* cx, const u8* p, usz off, usz n) {
  while (off < n) {
    usz next = sdt_feed_rest_step(cx, p, off, n);
    if (next == 0) return 0;
    off = next;
  }
  return off == n;
}

static int sdt_drive_hs_flight(struct sdt_client* cx, const u8* p, usz n) {
  usz ee_end = sdt_consume_ee(cx, p, n);
  if (ee_end == 0) return 0;
  return sdt_feed_rest(cx, p, ee_end, n);
}

static int sdt_open_handshake(struct sdt_client* cx, u8* pkt, usz len) {
  quic_span        tls;
  quic_appdata_pkt in = {quic_mspan_of(pkt, len), 6};
  if (!quic_client_open_handshake_wire(&cx->c, &in, &tls)) return 0;
  return sdt_drive_hs_flight(cx, tls.p, tls.n);
}

/* Seal our own Finished into a Handshake packet (CLIENT_HS, our own
 * direction) and send it. */
static int sdt_send_finished(struct sdt_client* cx) {
  u8                      fin[128], pkt[512];
  quic_obuf               fob = quic_obuf_of(fin, sizeof fin);
  quic_obuf               pkt_ob;
  quic_clientwire_seal_in sin;
  if (!quic_fullhs_send_finished(&cx->c.hs, &fob)) return 0;
  pkt_ob = quic_obuf_of(pkt, sizeof pkt);
  sin    = (quic_clientwire_seal_in){
      {quic_span_of(g_sdt_cli_scid, 6), quic_span_of(g_sdt_cli_scid, 6), 0},
      quic_span_of(fin, fob.len)};
  if (!quic_client_seal_handshake_wire(&cx->c, &sin, &pkt_ob)) return 0;
  return wired_udp_send(cx->fd, &cx->srv, quic_span_of(pkt, pkt_ob.len)) ==
         (i64)pkt_ob.len;
}

/* Confirm (RFC 9001 4.1.2): the 1-RTT keys were already derived right after
 * the server's Finished verified (sdt_handshake's advance_application call),
 * so this only needs the HANDSHAKE_DONE frame to have been observed. */
static int sdt_confirm(struct sdt_client* cx) {
  return quic_fullhs_confirmed(&cx->c.hs);
}

/* Open a 1-RTT reply payload (raw, so multiple coalesced frames can be
 * walked) with our own SERVER_AP key. */
static int sdt_open_onertt(
    struct sdt_client* cx, u8* pkt, usz len, const u8** pl, usz* pll) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  quic_span                v;
  if (!quic_keysched_get(&cx->c.tls.ks, QUIC_KS_SERVER_AP, &k)) return 0;
  quic_aes128_init(&hp, k->hp);
  {
    quic_protect_keys           pk = {k, &hp};
    quic_hspkt_onertt_open_desc d  = {quic_mspan_of(pkt, len), 6, 0};
    if (!quic_hspkt_onertt_open(&pk, &d, &v)) return 0;
  }
  *pl  = v.p;
  *pll = v.n;
  return 1;
}

/* 1 if this 1-RTT payload carries a HANDSHAKE_DONE frame (0x1e). */
static int sdt_payload_has_hs_done(const u8* pl, usz pll) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr))
    if (fr.type == 0x1e) return 1;
  return 0;
}

/* r is a usable 1-RTT (short-header) datagram: recv succeeded and byte0's
 * high bit is clear (a long-header Handshake ACK has it set). */
static int sdt_recv_is_onertt(i64 r, const u8* pkt) {
  return r > 0 && (pkt[0] & 0x80) == 0;
}

/* One receive attempt while waiting for the server's post-Finished reply.
 * RFC 9000 12.2: the confirmation coalesces a long-header Handshake ACK ahead
 * of the 1-RTT packet carrying HANDSHAKE_DONE in ONE datagram (srvloop's
 * emit_confirm) -- split it and check every slice, rather than assuming the
 * whole datagram is either all-long-header or all-short-header. Returns 1
 * once a 1-RTT slice carrying HANDSHAKE_DONE is seen, 0 to keep waiting. */
static int sdt_slice_has_hs_done(struct sdt_client* cx, const u8* p, usz n) {
  const u8* pl;
  usz       pll;
  if ((p[0] & 0x80) != 0) return 0; /* long header: Handshake ACK, not ours */
  if (!sdt_open_onertt(cx, (u8*)p, n, &pl, &pll)) return 0;
  return sdt_payload_has_hs_done(pl, pll);
}

static int sdt_try_recv_hs_done(struct sdt_client* cx) {
  u8               pkt[1500];
  quic_sockaddr_in from;
  const u8*        pkts[8];
  usz              offs[8], lens[8];
  quic_pktlist     plist = {pkts, offs, lens, 8};
  usz              n, i;
  i64 r = wired_udp_recvfrom(cx->fd, quic_mspan_of(pkt, sizeof pkt), &from);
  if (r <= 0) return 0;
  n = quic_udploop_split(quic_span_of(pkt, (usz)r), &plist);
  for (i = 0; i < n; i++)
    if (sdt_slice_has_hs_done(cx, pkt + offs[i], lens[i])) return 1;
  return 0;
}

/* The server's reply to our Finished coalesces a Handshake ACK (long header)
 * with a 1-RTT packet carrying SETTINGS + HANDSHAKE_DONE (same shape as
 * h3_loopback_test's test_loopback_wire_confirm_and_get). Poll until
 * HANDSHAKE_DONE is observed or the attempt budget runs out. */
static int sdt_wait_hs_done(struct sdt_client* cx) {
  for (int i = 0; i < 20; i++)
    if (sdt_try_recv_hs_done(cx)) return 1;
  return 0;
}

/* Everything up through the server's Finished: Initial exchange, ServerHello,
 * the Handshake flight (EE/Cert/CertVerify/Finished), then our own 1-RTT key
 * derivation (RFC 8446 4.4.4: legal as soon as the server's Finished
 * verifies) and our own Finished sent back. */
/* Initial exchange through opening the Handshake flight (EE/Cert/
 * CertVerify/Finished) -- the receive half of sdt_handshake_to_finished. */
static int sdt_recv_accept_flight(struct sdt_client* cx) {
  u8  ini_reply[1500], hs_reply[1500];
  usz ilen = 0, hlen = 0;
  if (!sdt_do_initial(
          cx, ini_reply, sizeof ini_reply, &ilen, hs_reply, sizeof hs_reply,
          &hlen))
    return 0;
  if (!sdt_open_initial(cx, ini_reply, ilen)) return 0;
  return sdt_open_handshake(cx, hs_reply, hlen);
}

/* Our own 1-RTT key derivation (RFC 8446 4.4.4: legal as soon as the
 * server's Finished verifies) and our own Finished sent back -- the send
 * half of sdt_handshake_to_finished. 1-RTT keys must be derived before
 * sdt_wait_hs_done, whose reply IS a 1-RTT packet (mirrors client.c's
 * do_confirm ordering, split across two calls since this test drives the
 * wire directly rather than through quic_client_feed). */
static int sdt_send_own_finished(struct sdt_client* cx) {
  if (!quic_fullhs_advance_application(&cx->c.hs)) return 0;
  return sdt_send_finished(cx);
}

/* Everything up through the server's Finished. */
static int sdt_handshake_to_finished(struct sdt_client* cx) {
  if (!sdt_recv_accept_flight(cx)) return 0;
  return sdt_send_own_finished(cx);
}

/* Everything from the Initial exchange through confirmation, once the client
 * socket is already open. */
static int sdt_handshake_over_socket(struct sdt_client* cx) {
  if (!sdt_handshake_to_finished(cx)) {
    wired_log_str("sdt: STAGE handshake (Initial..Finished) failed\n");
    return 0;
  }
  if (!sdt_wait_hs_done(cx)) {
    wired_log_str("sdt: STAGE handshake_done never observed\n");
    return 0;
  }
  return sdt_confirm(cx);
}

/* Bring the client all the way to a confirmed 1-RTT connection over the real
 * socket. Each phase is checked separately by the caller via the return
 * value / out-params, not folded into one opaque CHECK. */
static int sdt_handshake(struct sdt_client* cx) {
  sdt_client_init(cx);
  if (cx->fd < 0) return -1; /* sandbox: no sockets */
  return sdt_handshake_over_socket(cx);
}

/* --- Extended CONNECT (WebTransport) --------------------------------------
 */

/* Build a HEADERS-frame payload carrying an Extended CONNECT (RFC 9220 3 /
 * draft-ietf-webtrans-http3-15 3), the stream 0 request body -- framing as a
 * STREAM frame happens in sdt_seal_stream0 below (it needs the client's own
 * key schedule, unlike this pure encode step). */
static usz sdt_build_connect(u8* out, usz cap) {
  u8                   fields[256];
  quic_obuf            fob = quic_obuf_of(fields, sizeof fields);
  quic_obuf            hob = quic_obuf_of(out, cap);
  quic_h3req_pseudo_in pin = {
      quic_span_of((const u8*)"CONNECT", 7),
      quic_span_of((const u8*)"https", 5), quic_span_of((const u8*)"h", 1),
      quic_span_of((const u8*)"/", 1),
      quic_span_of((const u8*)"webtransport", 12)};
  if (!quic_h3req_enc_pseudo(&pin, &fob)) return 0;
  if (!quic_h3_frame_put(
          &hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fields, fob.len)))
    return 0;
  return hob.len;
}

/* Seal payload as a STREAM(0, offset 0, fin=0) 1-RTT packet under CLIENT_AP
 * (mirrors srvloop_test.c's client_seal_onertt shape, but keyed from our own
 * independently-derived schedule instead of peeking at wired_server's). */
static usz sdt_seal_stream0(
    struct sdt_client* cx, const u8* payload, usz plen, u8* out, usz cap) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  quic_appdata_tx          tx = {
      quic_span_of(g_sdt_cli_scid, 6), 0, 0, quic_span_of(payload, plen), 0};
  quic_obuf ob = quic_obuf_of(out, cap);
  if (!quic_keysched_get(&cx->c.tls.ks, QUIC_KS_CLIENT_AP, &k)) return 0;
  quic_aes128_init(&hp, k->hp);
  {
    quic_protect_keys pk = {k, &hp};
    if (!quic_appdata_send(&pk, &tx, &ob)) return 0;
  }
  return ob.len;
}

/* Send the Extended CONNECT stream frame over the wire. */
static int sdt_send_connect(struct sdt_client* cx) {
  u8  frame[512], pkt[512];
  usz flen = sdt_build_connect(frame, sizeof frame);
  usz plen;
  if (flen == 0) return 0;
  plen = sdt_seal_stream0(cx, frame, flen, pkt, sizeof pkt);
  if (plen == 0) return 0;
  return wired_udp_send(cx->fd, &cx->srv, quic_span_of(pkt, plen)) == (i64)plen;
}

/* 1 if this 1-RTT payload carries a STREAM frame on stream 0 whose data opens
 * with an H3 HEADERS frame encoding a 2xx status (":status" indexed entry 25
 * = 200 in the QPACK static table -- same shape wired_h3resp_prefix emits).
 * We don't need to fully QPACK-decode: srvrun's 200/403 status responses are
 * single-byte-indexed field lines for the handful of codes it ever sends
 * (200 -> static index 25, encoded as 0xc0|25 = 0xd9), so a direct byte
 * search after the HEADERS frame header is enough to prove "a 2xx came
 * back" without reimplementing QPACK client-side. */
/* Byte 0xd9 (QPACK :status 200 indexed line) anywhere in data. */
static int sdt_has_status_200_byte(const u8* data, u64 len) {
  for (u64 i = 0; i < len; i++)
    if (data[i] == 0xd9) return 1;
  return 0;
}

/* fr is a STREAM frame (RFC 9000 19.8 type range) on stream 0. */
/* fr.type is in the STREAM frame range (RFC 9000 19.8). */
static int sdt_is_stream_frame(const quic_framewalk_item* fr) {
  return fr->type >= 0x08 && fr->type <= 0x0f;
}

static int sdt_is_our_stream0(
    const quic_framewalk_item* fr, quic_stream_frame* sf) {
  if (!sdt_is_stream_frame(fr)) return 0;
  if (!quic_frame_get_stream(fr->start, fr->remaining, sf)) return 0;
  return sf->stream_id == 0;
}

/* fr is our stream-0 STREAM frame and its data carries the 2xx status byte.
 */
static int sdt_frame_has_2xx(const quic_framewalk_item* fr) {
  quic_stream_frame sf;
  if (!sdt_is_our_stream0(fr, &sf)) return 0;
  return sdt_has_status_200_byte(sf.data, sf.length);
}

static int sdt_stream0_has_2xx(const u8* pl, usz pll) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr))
    if (sdt_frame_has_2xx(&fr)) return 1;
  return 0;
}

/* One receive attempt while waiting for the CONNECT's 2xx: 1 if this
 * datagram was the 1-RTT reply and it carried the 2xx, 0 to keep waiting. */
static int sdt_try_recv_2xx(struct sdt_client* cx) {
  u8               pkt[1500];
  quic_sockaddr_in from;
  const u8*        pl;
  usz              pll;
  i64 r = wired_udp_recvfrom(cx->fd, quic_mspan_of(pkt, sizeof pkt), &from);
  if (!sdt_recv_is_onertt(r, pkt)) return 0;
  if (!sdt_open_onertt(cx, pkt, (usz)r, &pl, &pll)) return 0;
  return sdt_stream0_has_2xx(pl, pll);
}

/* Poll for a 1-RTT reply carrying the CONNECT's 2xx response, up to
 * max_tries * 1-recv-per-try (UDP recv is our only wait primitive here). */
static int sdt_wait_connect_2xx(struct sdt_client* cx, int max_tries) {
  for (int i = 0; i < max_tries; i++)
    if (sdt_try_recv_2xx(cx)) return 1;
  return 0;
}

/* --- DATAGRAM send + self-echo receive ------------------------------------
 */

/* CLIENT_AP key + its header-protection cipher, ready to seal a 1-RTT
 * packet. */
static int sdt_client_ap_key(struct sdt_client* cx, quic_protect_keys* pk) {
  const quic_initial_keys* k;
  static quic_aes128 hp; /* outlives the call, mirrors cw_dirkey's shape */
  if (!quic_keysched_get(&cx->c.tls.ks, QUIC_KS_CLIENT_AP, &k)) return 0;
  quic_aes128_init(&hp, k->hp);
  *pk = (quic_protect_keys){k, &hp};
  return 1;
}

/* Seal a QUIC DATAGRAM frame (RFC 9221 5) carrying payload into a 1-RTT
 * packet under CLIENT_AP and send it. */
/* Build a 1-RTT packet carrying one QUIC DATAGRAM frame (RFC 9221 5) over
 * payload into out, under CLIENT_AP. flen/frame are caller-owned scratch. */
static int sdt_build_datagram_pkt(
    struct sdt_client* cx,
    const u8*          payload,
    usz                n,
    u8*                frame,
    usz                frame_cap,
    quic_obuf*         out) {
  quic_mspan             fb   = quic_mspan_of(frame, frame_cap);
  quic_datagram_frame    df   = {n, payload};
  usz                    flen = quic_datagram_encode(fb, &df, 0);
  quic_protect_keys      pk;
  quic_hspkt_onertt_desc d = {
      quic_span_of(g_sdt_cli_scid, 6), 1, quic_span_of(frame, flen), 0};
  if (flen == 0) return 0;
  if (!sdt_client_ap_key(cx, &pk)) return 0;
  return quic_hspkt_onertt_build(&pk, &d, out);
}

static int sdt_send_datagram(struct sdt_client* cx, const u8* payload, usz n) {
  u8        frame[300], pkt[512];
  quic_obuf ob = quic_obuf_of(pkt, sizeof pkt);
  if (!sdt_build_datagram_pkt(cx, payload, n, frame, sizeof frame, &ob))
    return 0;
  return wired_udp_send(cx->fd, &cx->srv, quic_span_of(pkt, ob.len)) ==
         (i64)ob.len;
}

/* 1 if this 1-RTT payload carries a DATAGRAM frame whose bytes equal
 * want[0..want_len). */
static int sdt_bytes_eq(const u8* a, const u8* b, usz n) {
  u8 diff = 0;
  for (usz i = 0; i < n; i++) diff |= (u8)(a[i] ^ b[i]);
  return diff == 0;
}

static int sdt_is_datagram_frame(const quic_framewalk_item* fr) {
  return fr->type == QUIC_FRAME_DATAGRAM || fr->type == QUIC_FRAME_DATAGRAM_LEN;
}

/* fr is a DATAGRAM frame (RFC 9221 5) whose payload equals want[0..want_len).
 */
/* Decode fr as a DATAGRAM frame into *df. Returns 0 if fr is not one. */
static int sdt_decode_datagram(
    const quic_framewalk_item* fr, quic_datagram_frame* df) {
  if (!sdt_is_datagram_frame(fr)) return 0;
  return quic_datagram_decode(fr->start, fr->remaining, df) != 0;
}

static int sdt_datagram_matches(
    const quic_framewalk_item* fr, const u8* want, usz want_len) {
  quic_datagram_frame df;
  if (!sdt_decode_datagram(fr, &df)) return 0;
  if (df.length != want_len) return 0;
  return sdt_bytes_eq(df.data, want, want_len);
}

static int sdt_payload_has_our_datagram(
    const u8* pl, usz pll, const u8* want, usz want_len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr))
    if (sdt_datagram_matches(&fr, want, want_len)) return 1;
  return 0;
}

/* One receive attempt while draining replies after a DATAGRAM send: 1 if
 * this datagram was a 1-RTT reply carrying our own echoed payload, 0 to keep
 * draining, -1 once recv itself times out (nothing more queued this round).
 */
/* 1 if pkt/r is a usable 1-RTT reply carrying our own echoed payload, 0
 * otherwise (long header, AEAD failure, or no match) -- everything short of
 * "nothing queued", which the caller checks itself via r. */
static int sdt_onertt_is_our_echo(
    struct sdt_client* cx, i64 r, u8* pkt, const u8* payload, usz plen) {
  const u8* pl;
  usz       pll;
  if (!sdt_recv_is_onertt(r, pkt)) return 0;
  if (!sdt_open_onertt(cx, pkt, (usz)r, &pl, &pll)) return 0;
  return sdt_payload_has_our_datagram(pl, pll, payload, plen);
}

static int sdt_try_recv_echo(
    struct sdt_client* cx, const u8* payload, usz plen) {
  u8               pkt[1500];
  quic_sockaddr_in from;
  i64 r = wired_udp_recvfrom(cx->fd, quic_mspan_of(pkt, sizeof pkt), &from);
  if (r <= 0) return -1; /* nothing queued this round */
  return sdt_onertt_is_our_echo(cx, r, pkt, payload, plen);
}

/* Drain up to 5 replies for one send, looking for our own echo among them. */
static int sdt_drain_for_echo(
    struct sdt_client* cx, const u8* payload, usz plen) {
  for (int j = 0; j < 5; j++) {
    int r = sdt_try_recv_echo(cx, payload, plen);
    if (r != 0) return r > 0;
  }
  return 0;
}

/* One send-then-drain round. Returns 1 (echo seen), 0 (not this round), or
 * -1 (send itself failed -- fatal, the caller stops retrying). */
static int sdt_echo_round(struct sdt_client* cx, const u8* payload, usz plen) {
  if (!sdt_send_datagram(cx, payload, plen)) return -1;
  return sdt_drain_for_echo(cx, payload, plen);
}

/* Poll for our own DATAGRAM to be echoed back, retrying send+recv since RFC
 * 9221 datagrams are unreliable and the broadcast is best-effort. */
static int sdt_wait_datagram_echo(
    struct sdt_client* cx, const u8* payload, usz plen, int tries) {
  for (int i = 0; i < tries; i++) {
    int r = sdt_echo_round(cx, payload, plen);
    if (r != 0) return r;
  }
  return 0;
}

/* --- the test itself -------------------------------------------------------
 */

/* Full scenario: real srvthreads worker (--cores 0 equivalent), real
 * independent client, handshake -> WT CONNECT -> DATAGRAM self-echo. Each
 * stage CHECKs separately so a failure pinpoints where. Benign skip if the
 * sandbox forbids sockets/threads (matches every other real-socket test's
 * precedent, e.g. srvrun_test's sr_open_sockets). */
/* STAGE 2: WebTransport session establishment (Extended CONNECT -> 2xx). */
static int sdt_stage_wt_connect(struct sdt_client* cx) {
  return sdt_send_connect(cx) && sdt_wait_connect_2xx(cx, 40);
}

/* STAGE 3: the bug under test -- does our own DATAGRAM come back to us via
 * wired_server_broadcast_datagram under --cores (srvthreads)? */
static int sdt_stage_datagram_echo(struct sdt_client* cx) {
  const u8 msg[] = "hello-self";
  return sdt_wait_datagram_echo(cx, msg, sizeof msg - 1, 10) == 1;
}

/* Drive stages 2+3, CHECKing each independently so a failure pinpoints which
 * one; a stage only runs once its predecessor succeeded. Stage 1 (handshake)
 * is already done by the time this runs -- see test_srvthreads_datagram_
 * self_echo, which CHECKs it separately before calling this. */
static void sdt_run_wt_stages(struct sdt_client* cx) {
  int wt_ok = sdt_stage_wt_connect(cx);
  CHECK(wt_ok == 1);
  if (wt_ok) CHECK(sdt_stage_datagram_echo(cx) == 1);
}

/* STAGE 1 (handshake confirmation) plus everything downstream of it, run
 * once the worker thread is up: CHECKs stage 1 unless the sandbox forbids
 * sockets (hs_ok == -1, a benign skip, matching sr_open_sockets' precedent
 * elsewhere in this suite -- no CHECK at all in that case). */
static void sdt_run_from_handshake(struct sdt_client* cx) {
  int hs_ok = sdt_handshake(cx);
  if (hs_ok == -1) return;
  CHECK(hs_ok == 1);
  if (hs_ok == 1) sdt_run_wt_stages(cx);
}

/* Full scenario: real srvthreads worker (--cores 0 equivalent), real
 * independent client, handshake -> WT CONNECT -> DATAGRAM self-echo. Each
 * stage CHECKs separately so a failure pinpoints where. Benign skip if the
 * sandbox forbids sockets/threads (matches every other real-socket test's
 * precedent, e.g. srvrun_test's sr_open_sockets). */
static void test_srvthreads_datagram_self_echo(void) {
  wired_srvboot_id  id;
  u8                priv[32], pub[32], seed[32], rnd[32];
  wired_thread      srv_thread = {0};
  struct sdt_client cx         = {0};

  sdt_make_id(&id, priv, pub, seed, rnd);
  __atomic_store_n(wired_srvrun_shutdown_word(), 0, __ATOMIC_RELEASE);
  if (wired_thread_start(&srv_thread, sdt_server_thread, &id) < 0)
    return; /* sandbox: no thread support */

  sdt_run_from_handshake(&cx);

  wired_udp_close(cx.fd);
  __atomic_store_n(wired_srvrun_shutdown_word(), 1, __ATOMIC_RELEASE);
  wired_thread_join(&srv_thread);
}

/* --- direct root-cause confirmation (no handshake needed) ----------------
 *
 * The wire-level scenario above proves the bug end-to-end but is gated on a
 * pre-existing, unrelated SDK gap (quic_tlsdriver_recv_crypto's Transcript-
 * Hash input omits the ClientHello -- see sdt_open_initial's doc): every
 * existing unit test masks it by pairing two quic_tlsdriver instances that
 * both make the same substitution, so it has never been exercised against a
 * real independent peer before. Fixing that is out of this task's scope.
 *
 * This second test isolates the ACTUAL target bug at the unit level, the
 * same way tests/app/srvrun_test.c already pokes srvrun's internals directly
 * (sr_make_confirmed_conn et al. -- this file is unity-built into the same
 * translation unit as srvrun.c, so its file-scope `static` types/functions
 * and the g_srvrun_env global are visible here too). No socket, no TLS: it
 * marks a connection slot in a caller-owned wired_srvrun_env (exactly what
 * wired_srvthreads_run gives each worker via wired_srvrun_env_size/init) as
 * an up, WT-active connection, then calls the SAME public entry point
 * wt_on_datagram_cb calls, wired_server_broadcast_datagram, and shows it
 * finds zero targets -- because that function's <= 1-worker fallback path
 * (srvrun_broadcast_direct) always reads the process-global g_srvrun_env,
 * never the caller-owned env the connection actually lives in. A second,
 * positive-control call proves the connection itself was set up correctly:
 * calling srvrun_broadcast_to_all directly, pointed at the RIGHT env, DOES
 * queue the datagram. */

/* wired_srvrun_env is opaque outside srvrun.c's own TU; this file is unity-
 * built into that same TU (see the file doc above), so its full definition
 * is visible here too. Static, not stack: grew to ~9 MiB once respstore
 * became per-(conn,stream) (1 MiB -> 4 MiB) and the srvbigbuf pool (1.25
 * MiB) was added; 16 MiB leaves headroom since that call cannot be used in
 * a static array bound. */
static u8 g_sdt_env_storage[16u * 1024u * 1024u];

/* A connection slot with an active WebTransport session and its own SETTINGS
 * already sent (srvrun_queue_datagram's own gate, RFC 9297 2.1) -- the state
 * a real confirmed WT connection reaches, without running any handshake. */
static void sdt_mark_wt_active(srvrun_conn* c) {
  *c                    = (srvrun_conn){0};
  c->up                 = 1;
  c->wt_active          = 1;
  c->l.h3.settings_sent = 1;
  wired_wt_session_init(&c->wt, 0);
  wired_wt_session_establish(&c->wt);
}

/* STAGE 4 (the actual target bug, isolated): wired_server_broadcast_datagram
 * -- the exact call wt_on_datagram_cb makes -- must reach a WT-active
 * connection living in a caller-owned wired_srvrun_env (srvthreads' per-
 * worker shape). It does not: it always reads the process-global
 * g_srvrun_env, which this connection was never placed in. */
static void test_srvthreads_broadcast_misses_caller_owned_env(void) {
  wired_srvrun_env* env = (wired_srvrun_env*)(void*)g_sdt_env_storage;
  srvrun_state      st;
  srvrun_conn*      c;
  const u8          msg[] = "root-cause-probe";
  /* wired_srvrun_env's own layout (table[CAP] then conns[CAP] inline, see
   * srvrun.c's struct definition, visible in this same unity TU) -- NOT
   * srvrun_state, which holds two POINTERS, not inline arrays. Building an
   * srvrun_state view over env needs those two pointers, same shape as
   * srvrun_broadcast_direct's own local {g_srvrun_table, g_srvrun_state.
   * conns} construction. */
  st = (srvrun_state){env->table, env->conns};
  CHECK(sizeof g_sdt_env_storage >= wired_srvrun_env_size());
  wired_srvrun_env_init(env);
  c = &st.conns[0];
  sdt_mark_wt_active(c);

  CHECK(c->dg_pending == 0); /* baseline: nothing queued yet */
  CHECK(
      wired_server_broadcast_datagram(quic_span_of(msg, sizeof msg - 1)) == 1);
  /* THE BUG: the public broadcast API reports success (1) -- it always does,
   * srvrun_broadcast_direct has no target count to fail on -- but it never
   * actually reached this env's connection, because it iterated
   * g_srvrun_env's conns[], not env's. */
  CHECK(c->dg_pending == 0);

  /* POSITIVE CONTROL: the exact same connection, reached by pointing
   * srvrun_broadcast_to_all at the RIGHT env directly, DOES get queued --
   * proving sdt_mark_wt_active's setup is valid and srvrun_is_broadcast_
   * target/srvrun_queue_datagram themselves work correctly. The bug is
   * specifically in wired_server_broadcast_datagram's env selection, not in
   * the broadcast/queue logic it calls. */
  srvrun_broadcast_to_all(&st, quic_span_of(msg, sizeof msg - 1));
  CHECK(c->dg_pending == 1);
  CHECK(c->dg_pending_len == sizeof msg - 1);
  for (usz i = 0; i < sizeof msg - 1; i++)
    CHECK(c->dg_pending_buf[i] == msg[i]);
  /* THE FIX (verified in tests/app/srvinbox_test.c's
   * test_srvinbox_registry_single_worker_reaches_own_env, not repeated here):
   * once this thread calls wired_srvrun_broadcast_register(0, 1, row, env)
   * with THIS env, wired_server_broadcast_datagram finds this thread's
   * registry entry and fans out into env->conns directly instead of
   * g_srvrun_env's -- srvrun_broadcast_registered (srvrun.c). */
}

void test_srvthreads_datagram(void) {
  test_srvthreads_datagram_self_echo();
  test_srvthreads_broadcast_misses_caller_owned_env();
}
