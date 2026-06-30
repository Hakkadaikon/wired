#include "transport/packet/frame/frame/connctl.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* --- NEW_TOKEN (19.7) --- */

/* Write type and length varints at *off. Returns 1 ok, 0 on overflow. */
static int put_new_token_head(u8 *buf, usz cap, usz *off, u64 length) {
  if (!quic_varint_put(buf, cap, off, QUIC_FRAME_NEW_TOKEN)) return 0;
  return quic_varint_put(buf, cap, off, length);
}

usz quic_new_token_encode(u8 *buf, usz cap, const quic_new_token_frame *f) {
  usz off = 0;
  if (!put_new_token_head(buf, cap, &off, f->length)) return 0;
  if (!quic_put_bytes(buf, cap, &off, f->token, (usz)f->length)) return 0;
  return off;
}

/* Point f->token at f->length bytes at *off (n total). Returns 1 ok, 0 if
 * the token runs past n. */
static int take_token_view(
    const u8 *buf, usz n, usz *off, quic_new_token_frame *f) {
  if (*off + (usz)f->length > n) return 0;
  f->token = buf + *off;
  *off += (usz)f->length;
  return 1;
}

usz quic_new_token_decode(const u8 *buf, usz n, quic_new_token_frame *f) {
  usz off = 1; /* type byte */
  if (!quic_varint_take(buf, n, &off, &f->length)) return 0;
  if (!take_token_view(buf, n, &off, f)) return 0;
  return off;
}

/* --- RETIRE_CONNECTION_ID (19.16) --- */

usz quic_retire_cid_encode(u8 *buf, usz cap, u64 seq) {
  usz off = 0;
  if (!quic_varint_put(buf, cap, &off, QUIC_FRAME_RETIRE_CID)) return 0;
  if (!quic_varint_put(buf, cap, &off, seq)) return 0;
  return off;
}

usz quic_retire_cid_decode(const u8 *buf, usz n, u64 *seq) {
  usz off = 1; /* type byte */
  if (!quic_varint_take(buf, n, &off, seq)) return 0;
  return off;
}

/* --- PATH_CHALLENGE / PATH_RESPONSE (19.17 / 19.18) --- */

usz quic_path_encode(u8 *buf, usz cap, u8 type, const u8 data[QUIC_PATH_DATA]) {
  usz off = 0;
  if (cap == 0) return 0;
  buf[off++] = type;
  if (!quic_put_bytes(buf, cap, &off, data, QUIC_PATH_DATA)) return 0;
  return off;
}

/* The type byte at buf[0] is present and equals the expected type. */
static int type_is(const u8 *buf, usz n, u8 type) {
  return n != 0 && buf[0] == type;
}

usz quic_path_decode(const u8 *buf, usz n, u8 type, u8 data[QUIC_PATH_DATA]) {
  usz off = 1; /* type byte */
  if (!type_is(buf, n, type)) return 0;
  if (!quic_take_bytes(buf, n, &off, data, QUIC_PATH_DATA)) return 0;
  return off;
}

/* --- HANDSHAKE_DONE (19.20) --- */

usz quic_handshake_done_encode(u8 *buf, usz cap) {
  if (cap == 0) return 0;
  buf[0] = QUIC_FRAME_HANDSHAKE_DONE;
  return 1;
}

usz quic_handshake_done_decode(const u8 *buf, usz n) {
  if (n == 0 || buf[0] != QUIC_FRAME_HANDSHAKE_DONE) return 0;
  return 1;
}
