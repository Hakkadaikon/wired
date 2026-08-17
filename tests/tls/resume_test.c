#include "test.h"

/* RFC 8446 4.6.1 / RFC 9001 4.6 / RFC 9000 7, 8.1, 17.2.5 */
/* The opaque session blob round-trips every remembered field — ticket
 * bytes, issuance metadata, remembered max_data and the resumption PSK —
 * and a truncated or oversized blob is rejected without touching the
 * destination. */
static void test_resume_session_roundtrip(void) {
  resume r = {0}, back = {0};
  u8     tk[4]   = {9, 8, 7, 6};
  u8     psk[32] = {0};
  u8     blob[QUIC_RESUME_TICKET_MAX + 64];
  usz    n;
  for (usz i = 0; i < 32; i++) psk[i] = (u8)(0xA0 + i);
  CHECK(
      resume_store(
          &r, wired_span_of(tk, 4),
          &(resume_store_in){100, 50, 1000, psk, wired_span_of(0, 0)}) == 1);
  n = resume_session(&r, blob, sizeof blob);
  CHECK(n > 0);
  CHECK(resume_set_session(&back, wired_span_of(blob, n)) == 1);
  CHECK(back.have_ticket == 1 && back.ticket_len == 4);
  CHECK(back.ticket[0] == 9 && back.ticket[3] == 6);
  CHECK(back.issued_at == 100 && back.lifetime == 50 && back.max_data == 1000);
  CHECK(back.have_psk == 1 && back.psk[0] == 0xA0 && back.psk[31] == 0xBF);
  /* truncated blob rejected */
  CHECK(resume_set_session(&back, wired_span_of(blob, n - 1)) == 0);
  /* nothing stored -> no session bytes */
  {
    resume empty2 = {0};
    CHECK(resume_session(&empty2, blob, sizeof blob) == 0);
  }
}

/* Restored sessions feed 0-RTT: early keys from the stored PSK equal the
 * keys derived from the raw PSK directly (the existing deriver is the
 * oracle); without a PSK there is nothing to derive. */
static void test_resume_early_keys_from_session(void) {
  resume       r       = {0};
  u8           tk[4]   = {1, 1, 2, 2};
  u8           psk[32] = {0};
  u8           ch[8]   = {'c', 'h', 'b', 'y', 't', 'e', 's', '!'};
  initial_keys want, got;
  for (usz i = 0; i < 32; i++) psk[i] = (u8)(3 * i + 1);
  CHECK(
      resume_store(
          &r, wired_span_of(tk, 4),
          &(resume_store_in){1, 2, 3, psk, wired_span_of(0, 0)}) == 1);
  tls_early_keys(psk, ch, sizeof ch, &want);
  CHECK(resume_early_keys(&r, ch, sizeof ch, &got) == 1);
  for (usz i = 0; i < sizeof want.key; i++) CHECK(got.key[i] == want.key[i]);
  {
    resume nopsk = {0};
    CHECK(resume_early_keys(&nopsk, ch, sizeof ch, &got) == 0);
  }
}

/* RFC 6066 3: resumption server_name compatibility -- an omitted new name,
 * or a session that never remembered one, is always compatible; a present
 * new name must equal the remembered one (case-insensitively, RFC 6125
 * 6.4.1); a mismatched present name is not. */
static void test_resume_sni_compatible(void) {
  resume   r      = {0};
  u8       tk[2]  = {1, 2};
  const u8 host[] = "Example.COM";
  CHECK(
      resume_store(
          &r, wired_span_of(tk, 2),
          &(resume_store_in){
              1, 2, 3, 0, wired_span_of(host, sizeof(host) - 1)}) == 1);
  CHECK(r.sni_len == sizeof(host) - 1);
  /* omitted this time -> compatible regardless */
  CHECK(resume_sni_compatible(&r, wired_span_of(0, 0)) == 1);
  /* same name, different case -> compatible */
  {
    const u8 same[] = "example.com";
    CHECK(
        resume_sni_compatible(&r, wired_span_of(same, sizeof(same) - 1)) == 1);
  }
  /* different name -> not compatible */
  {
    const u8 other[] = "other.example";
    CHECK(
        resume_sni_compatible(&r, wired_span_of(other, sizeof(other) - 1)) ==
        0);
  }
  /* a session that never remembered a server_name accepts any new one */
  {
    resume   nosni  = {0};
    u8       tk2[2] = {3, 4};
    const u8 any[]  = "anything.example";
    CHECK(
        resume_store(
            &nosni, wired_span_of(tk2, 2),
            &(resume_store_in){1, 2, 3, 0, wired_span_of(0, 0)}) == 1);
    CHECK(nosni.sni_len == 0);
    CHECK(
        resume_sni_compatible(&nosni, wired_span_of(any, sizeof(any) - 1)) ==
        1);
  }
}

void test_resume(void) {
  test_resume_session_roundtrip();
  test_resume_early_keys_from_session();
  test_resume_sni_compatible();
  resume r     = {0};
  u8     tk[4] = {1, 2, 3, 4};

  /* store succeeds and records the ticket */
  CHECK(
      resume_store(
          &r, wired_span_of(tk, sizeof tk),
          &(resume_store_in){100, 50, 1000, 0, wired_span_of(0, 0)}) == 1);
  CHECK(r.have_ticket == 1);
  CHECK(r.ticket_len == 4);
  CHECK(r.ticket[0] == 1 && r.ticket[3] == 4);

  /* RFC 8446 4.6.1: valid within lifetime, boundary at issued_at+lifetime */
  CHECK(resume_valid(&r, 100) == 1); /* at issuance */
  CHECK(resume_valid(&r, 149) == 1); /* last valid second */
  CHECK(resume_valid(&r, 150) == 0); /* boundary: expired */
  CHECK(resume_valid(&r, 200) == 0); /* well past */

  /* no ticket -> never valid */
  resume empty = {0};
  CHECK(resume_valid(&empty, 0) == 0);

  /* RFC 9000 7.4.1: remembered <= new is compatible, > is not */
  CHECK(resume_tp_compatible(1000, 1000) == 1); /* equal */
  CHECK(resume_tp_compatible(1000, 2000) == 1); /* new larger */
  CHECK(resume_tp_compatible(1000, 999) == 0);  /* new smaller */

  /* RFC 9001 4.6: 0-RTT needs ticket valid AND tp compatible */
  CHECK(resume_can_0rtt(&r, 1, 1) == 1);
  CHECK(resume_can_0rtt(&r, 0, 1) == 0);     /* ticket invalid */
  CHECK(resume_can_0rtt(&r, 1, 0) == 0);     /* tp incompatible */
  CHECK(resume_can_0rtt(&empty, 1, 1) == 0); /* no ticket */

  /* RFC 9000 8.1 / 17.2.5: Retry does not invalidate resumption */
  CHECK(resume_after_retry(&r, 1) == 1);
  CHECK(resume_after_retry(&r, 0) == 1);
  CHECK(resume_after_retry(&empty, 1) == 0);

  /* RFC 8446 4.6.1: oversized ticket is rejected */
  u8     big[QUIC_RESUME_TICKET_MAX + 1] = {0};
  resume r2                              = {0};
  CHECK(
      resume_store(
          &r2, wired_span_of(big, sizeof big),
          &(resume_store_in){0, 10, 0, 0, wired_span_of(0, 0)}) == 0);
  CHECK(r2.have_ticket == 0);
}
