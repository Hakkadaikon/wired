#include "app/http3/server/srvloop/respond_impl.h"

static u32 ticket_max_early_data(const wired_server* s);
static usz build_ticket_message(const wired_server* s, u8* msg, usz msg_cap);
static int append_ticket_frame(const wired_server* s, wired_obuf* out);
static int ncid_frame_owed(const wired_srvloop* l);
static int append_ncid_frame(const wired_srvloop* l, wired_obuf* out);
static int confirm_head(
    const wired_server* s, wired_srvloop* l, wired_obuf* out);
static void confirm_cache_store(wired_srvloop* l, const u8* p, usz n);

/* RFC 9114 6.2.1: wrap the control-stream type + SETTINGS in a STREAM frame on
 * the first server unidirectional stream (id 3, no FIN: the stream stays open).
 * The control stream is HTTP/3-only: on an hq-interop connection there is
 * nothing to open (lsquic's hq client mixed a stray SETTINGS stream's bytes
 * into the response body it saved). */
int srvloop_build_settings_frame(
    const wired_server* s, wired_srvloop* l, wired_obuf* out) {
  u8           ctl[H3SETTINGS_CONTROL_STREAM_MAX];
  wired_obuf   ctlb = obuf_of(ctl, sizeof ctl);
  stream_frame f;
  if (s->sdrv.alpn != SALPN_H3) {
    return 1;
  }
  /* advertise WebTransport + H3 datagrams only when the QUIC transport also
   * negotiated max_datagram_frame_size (RFC 9297 2.1.1 MUST) */
  if (!wired_h3srv_open_control(
          &l->h3, l->we_advertised_max_datagram > 0, &ctlb)) {
    return 0;
  }
  l->ctrl_settings_len = ctlb.len;
  f = (stream_frame){WIRED_SRVLOOP_CTRL_STREAM, 0, ctlb.len, ctl, 0};
  return appdata_stream_frame(&f, out);
}

/* RFC 8446 4.6.1 / RFC 9001 4: the seed session-ticket keys derive from
 * (srvkeys: drawn from the CSPRNG once per process, never compiled in); the
 * key rotates every KEYRING_PERIOD_SECS (keyring.h). 0 when the draw
 * failed, which leaves resumption disabled for an app that hands this to
 * wired_srvboot_id.ticket_key. */
const u8* wired_srvloop_ticket_key(void) {
  return srvkeys_ready() ? srvkeys_ticket() : 0;
}

static u32 ticket_max_early_data(const wired_server* s) {
  return sdrv_early_allowed(&s->sdrv) ? WIRED_SRVLOOP_MAX_EARLY_DATA_SIZE : 0;
}

static usz build_ticket_message(const wired_server* s, u8* msg, usz msg_cap) {
  /* RFC 8446 4.2.10 alpn; ticket_nonce 0: one ticket per connection, so
   * it is unique across this connection's tickets (RFC 8446 4.6.1). */
  ticket t = {{0}, 0, 7200, 0, (u8)s->sdrv.alpn, 0, s->sdrv.cipher_suite, {0}};
  u8     key[KEYRING_KEY];
  t.issued_at = wired_clock_epoch_secs();
  if (!srvkeys_ready()) {
    return 0;
  }
  if (!wired_server_resumption_secret(s, t.secret)) {
    return 0;
  }
  bytes_memcpy(t.sni, s->sdrv.sni_digest, TICKET_SNI_LEN); /* RFC 6066 3 */
  keyring_key(srvkeys_ticket(), t.issued_at, 0, key);
  return tls_new_session_ticket_encode(
      msg, msg_cap, &t, key, ticket_max_early_data(s));
}

/* Seal a fresh session ticket and append it as a CRYPTO frame
 * (RFC 9000 19.6) to a 1-RTT payload. */
static int append_ticket_frame(const wired_server* s, wired_obuf* out) {
  u8           msg[64 + TICKET_SEALED_LEN];
  crypto_frame cf;
  usz          written;
  usz          mlen = build_ticket_message(s, msg, sizeof msg);
  if (mlen == 0) {
    return 0;
  }
  cf      = (crypto_frame){0, mlen, msg};
  written = frame_put_crypto(out->p + out->len, out->cap - out->len, &cf);
  if (written == 0) {
    return 0;
  }
  out->len += written;
  return 1;
}

/* RFC 9000 5.1.1/19.15: hand the client its one spare connection ID at
 * confirmation -- a client holding no unused CID must not initiate
 * migration (RFC 9000 9), which left the interop connectionmigration case
 * stuck on its original path. No spare issued (len 0) appends nothing. */
/* The frame is owed only when a spare exists AND the preferred_address
 * parameter did not already deliver it (same CID, sequence 1). */
static int ncid_frame_owed(const wired_srvloop* l) {
  return l->spare_cid_len && !l->spare_cid_in_tp;
}

static int append_ncid_frame(const wired_srvloop* l, wired_obuf* out) {
  ncid_frame f;
  usz        written;
  if (!ncid_frame_owed(l)) {
    return 1;
  }
  f.seq             = 1;
  f.retire_prior_to = 0;
  f.cid_len         = l->spare_cid_len;
  bytes_memcpy(f.cid, l->spare_cid, l->spare_cid_len);
  bytes_memcpy(f.token, l->spare_cid_token, NCID_TOKEN);
  written = ncid_encode(out->p + out->len, out->cap - out->len, &f);
  if (written == 0) {
    return 0;
  }
  out->len += written;
  return 1;
}

/* SETTINGS (RFC 9114 6.2.1), a session ticket (RFC 8446 4.6.1), then the
 * spare connection ID (RFC 9000 19.15) -- the head of the confirmation
 * payload. */
static int confirm_head(
    const wired_server* s, wired_srvloop* l, wired_obuf* out) {
  if (!srvloop_build_settings_frame(s, l, out)) {
    return 0;
  }
  if (!append_ticket_frame(s, out)) {
    return 0;
  }
  return append_ncid_frame(l, out);
}

/* Capture the confirmation frames for a later replay
 * (wired_srvloop_reconfirm); an oversized payload simply leaves the cache
 * empty (no replay available) rather than truncating. */
static void confirm_cache_store(wired_srvloop* l, const u8* p, usz n) {
  if (n > sizeof l->confirm_frames) {
    return;
  }
  bytes_memcpy(l->confirm_frames, p, n);
  l->confirm_frames_len = (u16)n;
}

/* The 1-RTT payload sent at confirmation: confirm_head, then HANDSHAKE_DONE
 * (RFC 9000 19.20) last — callers rely on HANDSHAKE_DONE being the trailing
 * frame. */
int srvloop_confirm_payload(const wired_srvloop_conn* c, wired_obuf* out) {
  wired_obuf ob = obuf_of(out->p, out->cap);
  usz        a;
  if (!confirm_head(c->s, c->l, &ob)) {
    return 0;
  }
  a  = ob.len;
  ob = obuf_of(out->p + a, out->cap - a);
  if (!wired_server_handshake_done(c->s, &ob)) {
    return 0;
  }
  out->len = a + ob.len;
  confirm_cache_store(c->l, out->p, out->len);
  return 1;
}
