#include "tls/handshake/core/sdrv/sdrv_impl.h"

static void sdrv_copy32(u8* dst, const u8* src);
static int  sdrv_has_san_ipv4(const sdrv* s);
static void sdrv_build_cert(sdrv* s, u64 now_secs);
static int  sdrv_use_chain(const sdrv_init_in* in);
static void sdrv_take_chain(sdrv* s, const sdrv_init_in* in);
static void sdrv_copy_san_ipv4(sdrv* s, const u8* san_ipv4);
static void sdrv_copy_key(u8 dst[TICKET_KEY_LEN], const u8* src);
static void sdrv_copy_ticket_key(sdrv* s, const u8* ticket_key);
static void sdrv_reset_nego(sdrv* s);
static void sdrv_reset_hs(sdrv* s);

/* RFC 8446 4 / RFC 9001 4: drive the server handshake flight. */

static void sdrv_copy32(u8* dst, const u8* src) {
  for (usz i = 0; i < 32; i++) {
    dst[i] = src[i];
  }
}

/* 0 if s->san_ipv4 is all-zero (the zero-initialized default, meaning "no
 * IPv4 SAN requested" -- 0.0.0.0 is never a real peer). */
static int sdrv_has_san_ipv4(const sdrv* s) {
  for (usz i = 0; i < 4; i++) {
    if (s->san_ipv4[i]) {
      return 1;
    }
  }
  return 0;
}

/* RFC 5480 / RFC 5280 4.1: build the self-signed P-256 end-entity certificate
 * from p256_priv into the owned buffer and record it as the 1-entry chain to
 * send. now_secs anchors the validity window (see
 * sdrv_init_in.now_secs's doc). */
static void sdrv_build_cert(sdrv* s, u64 now_secs) {
  ec_point q;
  u8       pub_x[32], pub_y[32];
  ec_mul(&q, s->p256_priv, &p256_g);
  p256_fp_to_be(pub_x, q.x);
  p256_fp_to_be(pub_y, q.y);
  {
    const u8*    ip = sdrv_has_san_ipv4(s) ? s->san_ipv4 : 0;
    p256cert_key k  = {s->p256_priv, pub_x, pub_y, ip, now_secs};
    wired_obuf   o  = obuf_of(s->cert_buf, sizeof(s->cert_buf));
    p256cert_build(&k, &o);
    s->certs[0]   = wired_span_of(s->cert_buf, o.len);
    s->cert_count = 1;
  }
}

/* in carries a non-empty externally issued chain to use instead of a
 * self-signed certificate. */
static int sdrv_use_chain(const sdrv_init_in* in) {
  return in->chain != 0 && in->chain_count != 0;
}

/* Record in->chain (leaf first) as the certificate_list to send. Over
 * TLS_CERT_CHAIN_MAX entries fails closed: cert_count stays 0 and the
 * flight becomes unbuildable, rather than overflowing s->certs. */
static void sdrv_take_chain(sdrv* s, const sdrv_init_in* in) {
  if (in->chain_count > TLS_CERT_CHAIN_MAX) {
    s->cert_count = 0;
    return;
  }
  for (usz i = 0; i < in->chain_count; i++) {
    s->certs[i] = in->chain[i];
  }
  s->cert_count = in->chain_count;
}

/* Copy in->san_ipv4 into s->san_ipv4[4], or zero it (the "omit" sentinel,
 * see sdrv_has_san_ipv4) when in->san_ipv4 is 0. */
static void sdrv_copy_san_ipv4(sdrv* s, const u8* san_ipv4) {
  for (usz i = 0; i < 4; i++) {
    s->san_ipv4[i] = san_ipv4 ? san_ipv4[i] : 0;
  }
}

/* Copy a TICKET_KEY_LEN-byte key into dst, or zero dst when src is 0. */
static void sdrv_copy_key(u8 dst[TICKET_KEY_LEN], const u8* src) {
  for (usz i = 0; i < TICKET_KEY_LEN; i++) {
    dst[i] = src ? src[i] : 0;
  }
}

/* Copy ticket_key into s as both generations and record whether
 * resumption is enabled (ticket_key set). */
static void sdrv_copy_ticket_key(sdrv* s, const u8* ticket_key) {
  s->has_ticket_key     = ticket_key != 0;
  s->early_data_enabled = 0;
  sdrv_copy_key(s->ticket_key, ticket_key);
  sdrv_copy_key(s->ticket_key_prev, ticket_key);
}

void sdrv_set_ticket_key_prev(sdrv* s, const u8* prev) {
  sdrv_copy_key(s->ticket_key_prev, prev);
}

void sdrv_set_early_data(sdrv* s, int on) { s->early_data_enabled = on; }

void sdrv_set_raw_alpns(sdrv* s, const char* raw_alpns) {
  s->raw_alpns = raw_alpns;
}

void sdrv_set_alpn_client_order(sdrv* s, int on) {
  s->alpn_client_order = on != 0;
}

/* Negotiation defaults before any ClientHello is seen. */
static void sdrv_reset_nego(sdrv* s) {
  s->limits                       = (stp_limits){0};
  s->sreset_token_set             = 0;
  s->peer_max_datagram_frame_size = 0;
  s->alpn                         = SALPN_NONE;
  s->alpn_tok                     = wired_span_of(0, 0);
  s->raw_alpns                    = 0;
  s->alpn_client_order            = 0;
  s->cipher_suite                 = TLS_AES_128_GCM_SHA256;
  s->group                        = GROUP_X25519;
}

/* Per-handshake progress: CIDs, PSK/0-RTT/HRR outcomes, versions. */
static void sdrv_reset_hs(sdrv* s) {
  s->hs_ready            = 0;
  s->odcid_len           = 0;
  s->iscid_len           = 0;
  s->tp_odcid_len        = 0;
  s->rscid_len           = 0;
  s->psk_accepted        = 0;
  s->early_data_accepted = 0;
  s->early_keys_dropped  = 0;
  s->last_error          = 0;
  s->hrr_needed          = 0;
  s->hrr_sent            = 0;
  s->hrr_cipher_suite    = 0;
  s->sni_outcome         = SALPN_SNI_ABSENT;
  s->client_version      = 0;
  s->negotiated_version  = 0;
  s->pref_cid_len        = 0;
  for (usz i = 0; i < sizeof s->ch1_hash; i++) {
    s->ch1_hash[i] = 0;
  }
  bytes_memset(s->sni_digest, 0, sizeof s->sni_digest);
  s->cert_sigs_offered = 0;
}

void sdrv_init(sdrv* s, const sdrv_init_in* in) {
  sdrv_reset_nego(s);
  sdrv_copy32(s->server_priv, in->server_priv_x25519);
  sdrv_copy32(s->server_pub, in->server_pub_x25519);
  sdrv_copy32(s->p256_priv, in->sign_priv);
  sdrv_copy_san_ipv4(s, in->san_ipv4);
  sdrv_copy_ticket_key(s, in->ticket_key);
  if (sdrv_use_chain(in)) {
    sdrv_take_chain(s, in);
  } else {
    sdrv_build_cert(s, in->now_secs);
  }
  sdrv_reset_hs(s);
  transcript_init(&s->tr);
}

void sdrv_set_client_version(sdrv* s, u32 version) {
  s->client_version = version;
}
