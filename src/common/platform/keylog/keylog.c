#include "common/platform/keylog/keylog.h"

#include "common/bytes/util/bytes.h"
#include "common/platform/fio/fio.h"

#define KEYLOG_CR_HEXLEN 64 /* 32-byte client_random as lowercase hex */
#define KEYLOG_LABEL_MAX 64 /* longest NSS label, e.g.
                               CLIENT_HANDSHAKE_TRAFFIC_SECRET, with room */
#define KEYLOG_SECRET_MAX 128 /* generous cap for a TLS 1.3 traffic secret */
/* label + ' ' + cr-hex + ' ' + secret-hex + '\n' */
#define KEYLOG_LINE_MAX \
  (KEYLOG_LABEL_MAX + 1 + KEYLOG_CR_HEXLEN + 1 + 2 * KEYLOG_SECRET_MAX + 1)

static const char keylog_hexdigit[] = "0123456789abcdef";

/* Append the two lowercase hex digits of one byte into buf at *off. */
static int keylog_put_hexbyte(quic_mspan buf, usz *off, u8 b) {
  u8 pair[2] = {keylog_hexdigit[b >> 4], keylog_hexdigit[b & 0xF]};
  return quic_put_bytes(buf, off, quic_span_of(pair, 2));
}

/* Append the lowercase hex encoding of src into buf at *off. */
static int keylog_put_hex(quic_mspan buf, usz *off, quic_span src) {
  for (usz i = 0; i < src.n; i++)
    if (!keylog_put_hexbyte(buf, off, src.p[i])) return 0;
  return 1;
}

static int keylog_put_str(quic_mspan buf, usz *off, const char *s) {
  return quic_put_bytes(buf, off, quic_span_of((const u8 *)s, quic_cstr_len(s)));
}

static int keylog_put_char(quic_mspan buf, usz *off, u8 c) {
  return quic_put_bytes(buf, off, quic_span_of(&c, 1));
}

/* "label " */
static int keylog_build_label(quic_mspan line, usz *off, const char *label) {
  if (!keylog_put_str(line, off, label)) return 0;
  return keylog_put_char(line, off, ' ');
}

/* "cr-hex " */
static int keylog_build_cr(
    quic_mspan line, usz *off, const u8 client_random[32]) {
  if (!keylog_put_hex(line, off, quic_span_of(client_random, 32))) return 0;
  return keylog_put_char(line, off, ' ');
}

/* "label cr-hex " */
static int keylog_build_head(
    quic_mspan line, usz *off, const char *label,
    const u8 client_random[32]) {
  if (!keylog_build_label(line, off, label)) return 0;
  return keylog_build_cr(line, off, client_random);
}

/* "secret-hex\n" */
static int keylog_build_tail(quic_mspan line, usz *off, quic_span secret) {
  if (!keylog_put_hex(line, off, secret)) return 0;
  return keylog_put_char(line, off, '\n');
}

/* Build "label cr-hex secret-hex\n" into line, advancing *off. */
static int keylog_build(
    quic_mspan line, usz *off, const char *label, const u8 client_random[32],
    quic_span secret) {
  if (!keylog_build_head(line, off, label, client_random)) return 0;
  return keylog_build_tail(line, off, secret);
}

ssz wired_keylog_append(
    const char *path, const char *label, const u8 client_random[32],
    quic_span secret) {
  u8  line[KEYLOG_LINE_MAX];
  usz off = 0;
  if (!keylog_build(quic_mspan_of(line, sizeof line), &off, label,
                     client_random, secret))
    return WIRED_FIO_ETOOBIG;
  return wired_fio_append(path, quic_span_of(line, off));
}
