#include "tls/handshake/core/sdrv/sdrv_impl.h"

static int  sdrv_ch_run_gates(sdrv* s, const u8* ch_msg, usz ch_len);
static void sdrv_hrr_reset_transcript(sdrv* s, const u8* hrr, usz hrr_len);

static int sdrv_ch_run_gates(sdrv* s, const u8* ch_msg, usz ch_len) {
  for (usz i = 0; i < SDRV_CH_GATE_COUNT; i++) {
    if (!SDRV_CH_GATES[i](s, ch_msg, ch_len)) {
      return 0;
    }
  }
  return 1;
}

int sdrv_recv_client_hello(sdrv* s, const u8* ch_msg, usz ch_len) {
  s->last_error = 0;
  s->hrr_needed = 0;
  if (!sdrv_ch_run_gates(s, ch_msg, ch_len)) {
    return 0;
  }
  return sdrv_ch_after_gate(s, ch_msg, ch_len);
}

salpn_sni_outcome sdrv_sni_outcome(const sdrv* s) { return s->sni_outcome; }

int sdrv_enforce_sni(sdrv* s) {
  if (s->sni_outcome != SALPN_SNI_MISMATCH) {
    return 1;
  }
  s->last_error = err_crypto(TLS_ALERT_UNRECOGNIZED_NAME);
  return 0;
}

int sdrv_hrr_pending(const sdrv* s) { return s->hrr_needed; }

/* RFC 8446 4.4.1: replace ClientHello1 in the transcript with the synthetic
 * message_hash message (msg_type 254, body Hash(ClientHello1)) built over
 * s->ch1_hash, then fold in the just-built HRR bytes -- the transcript is
 * reset first since ClientHello1 was never folded in (sdrv_ch_arm_hrr only
 * hashed it, see its doc). */
static void sdrv_hrr_reset_transcript(sdrv* s, const u8* hrr, usz hrr_len) {
  u8  mh[4 + TLS_HASH_MAX];
  usz mh_len = hrr_message_hash(
      s->ch1_hash, tls_hash_of(s->cipher_suite)->len, mh, sizeof(mh));
  transcript_init(&s->tr);
  transcript_add(&s->tr, mh, mh_len);
  transcript_add(&s->tr, hrr, hrr_len);
}

int sdrv_build_hrr(sdrv* s, wired_obuf* out) {
  if (!hrr_build(s->cipher_suite, s->group, wired_span_of(0, 0), out)) {
    return 0;
  }
  sdrv_hrr_reset_transcript(s, out->p, out->len);
  s->hrr_sent   = 1;
  s->hrr_needed = 0;
  return 1;
}

u64 sdrv_last_error(const sdrv* s) { return s->last_error; }

int sdrv_handshake_secret(const sdrv* s, const u8** secret) {
  if (!s->hs_ready) {
    return 0;
  }
  *secret = s->hs_secret;
  return 1;
}

int sdrv_early_keys(const sdrv* s, initial_keys* out) {
  if (!s->early_data_accepted || s->early_keys_dropped) {
    return 0;
  }
  *out = s->early_keys;
  return 1;
}

void sdrv_discard_early_keys(sdrv* s) {
  bytes_memset(&s->early_keys, 0, sizeof s->early_keys);
  s->early_keys_dropped = 1;
}
