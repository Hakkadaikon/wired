#include "transport/conn/loop/crecv/message.h"

void crecv_message(const crecv* s, const u8** msg, usz* len) {
  crecv_message_at(s, 0, msg, len);
}

void crecv_message_at(const crecv* s, usz off, const u8** msg, usz* len) {
  *msg = s->buf + off;
  *len = off < s->received_to ? s->received_to - off : 0;
}

/* RFC 8446 4: handshake message = 1-byte type + 3-byte big-endian body len. */
static usz msg_total(const u8* b) {
  return 4 + ((usz)b[1] << 16 | (usz)b[2] << 8 | (usz)b[3]);
}

int crecv_complete_message(const crecv* s) {
  return crecv_complete_message_at(s, 0);
}

int crecv_complete_message_at(const crecv* s, usz off) {
  if (s->received_to < off + 4) return 0;
  return off + msg_total(s->buf + off) <= s->received_to;
}
