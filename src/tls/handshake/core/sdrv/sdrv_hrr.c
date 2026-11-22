#include "common/bytes/util/be.h"
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

/* The alert each salpn_sni_outcome closes with, 0 = continue: RFC 6066 3
 * unrecognized_name on a mismatch, RFC 8446 6.2 decode_error (50) on an
 * extension that does not parse. */
static const u8 SDRV_SNI_ALERT[] = {
    [SALPN_SNI_ABSENT]    = 0,
    [SALPN_SNI_MATCH]     = 0,
    [SALPN_SNI_MISMATCH]  = TLS_ALERT_UNRECOGNIZED_NAME,
    [SALPN_SNI_MALFORMED] = 50,
};

int sdrv_enforce_sni(sdrv* s) {
  u8 alert = SDRV_SNI_ALERT[s->sni_outcome];
  if (alert == 0) {
    return 1;
  }
  s->last_error = err_crypto(alert);
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

/* RFC 8446 4.2.2: the cookie extension ClientHello2 must carry -- type,
 * length and the opaque cookie<1..2^16-1> holding this driver's cookie. */
static int sdrv_cookie_echoed(const sdrv* s, wired_span ext) {
  u8 want[6 + SDRV_HRR_COOKIE_LEN];
  be_put_be16(want, EXT_COOKIE);
  be_put_be16(want + 2, 2 + SDRV_HRR_COOKIE_LEN);
  be_put_be16(want + 4, SDRV_HRR_COOKIE_LEN);
  bytes_memcpy(want + 6, s->hrr_cookie, SDRV_HRR_COOKIE_LEN);
  return ext.n == sizeof want && ct_diffn(ext.p, want, sizeof want) == 0;
}

/* RFC 8446 4.2.2: after our HRR the cookie must come back unchanged; before
 * it a cookie can only be stale or forged (clients MUST NOT send one in an
 * initial ClientHello) -- this stateful server has nothing to check it
 * against. */
static int sdrv_cookie_ok(const sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  int        found = sdrv_find_client_ext(ch_msg, ch_len, EXT_COOKIE, &ext);
  if (!s->hrr_sent) {
    return !found;
  }
  return found && sdrv_cookie_echoed(s, ext);
}

/* RFC 8446 4.1.2 / 4.2.2: a missing, altered or unsolicited cookie is
 * illegal_parameter (alert 47). */
int sdrv_ch_check_cookie(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (sdrv_cookie_ok(s, ch_msg, ch_len)) {
    return 1;
  }
  s->last_error = err_crypto(47);
  return 0;
}

int sdrv_build_hrr(sdrv* s, wired_obuf* out) {
  wired_span ck = wired_span_of(s->hrr_cookie, SDRV_HRR_COOKIE_LEN);
  if (!rng_bytes(s->hrr_cookie, SDRV_HRR_COOKIE_LEN)) {
    return 0;
  }
  if (!hrr_build(s->cipher_suite, s->group, ck, out)) {
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
