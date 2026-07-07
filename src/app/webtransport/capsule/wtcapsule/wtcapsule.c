#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"

#include "app/http3/core/capsule/capsule.h"
#include "common/bytes/util/be.h"

#define QUIC_WTCAPSULE_TYPE_CLOSE 0x2843ULL
#define QUIC_WTCAPSULE_TYPE_DRAIN 0x78aeULL
#define QUIC_WTCAPSULE_CLOSE_CODE_LEN 4

int quic_wtcapsule_encode_close(
    quic_obuf* out, u32 app_error_code, quic_span message) {
  u8  body[QUIC_WTCAPSULE_CLOSE_CODE_LEN + QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX];
  usz i;
  if (message.n > QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX) return 0;
  quic_put_be32(body, app_error_code);
  for (i = 0; i < message.n; i++)
    body[QUIC_WTCAPSULE_CLOSE_CODE_LEN + i] = message.p[i];
  return quic_capsule_encode(
      out, QUIC_WTCAPSULE_TYPE_CLOSE,
      quic_span_of(body, QUIC_WTCAPSULE_CLOSE_CODE_LEN + message.n));
}

int quic_wtcapsule_encode_drain(quic_obuf* out) {
  return quic_capsule_encode(
      out, QUIC_WTCAPSULE_TYPE_DRAIN, quic_span_of(0, 0));
}

/* 1 iff type/value is a well-formed WT_CLOSE_SESSION capsule: the right
 * type, long enough for the 32-bit error code, and its message within the
 * WT-level cap. */
static int wtcapsule_is_close(u64 type, quic_span value) {
  return type == QUIC_WTCAPSULE_TYPE_CLOSE &&
         value.n >= QUIC_WTCAPSULE_CLOSE_CODE_LEN &&
         value.n - QUIC_WTCAPSULE_CLOSE_CODE_LEN <=
             QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX;
}

/* Split out of quic_wtcapsule_decode_close to keep it at CCN<=3: this
 * unconditionally reads app_error_code/message out of an already-validated
 * WT_CLOSE_SESSION value. */
static void wtcapsule_take_close(
    quic_span value, u32* app_error_code, quic_span* message) {
  *app_error_code = quic_get_be32(value.p);
  *message        = quic_span_of(
      value.p + QUIC_WTCAPSULE_CLOSE_CODE_LEN,
      value.n - QUIC_WTCAPSULE_CLOSE_CODE_LEN);
}

int quic_wtcapsule_decode_close(
    quic_span data, usz* at, u32* app_error_code, quic_span* message) {
  usz       local_at = *at;
  u64       type;
  quic_span value;
  if (!quic_capsule_decode(data, &local_at, &type, &value)) return 0;
  if (!wtcapsule_is_close(type, value)) return 0;
  wtcapsule_take_close(value, app_error_code, message);
  *at = local_at;
  return 1;
}

int quic_wtcapsule_decode_drain(quic_span data, usz* at) {
  usz       local_at = *at;
  u64       type;
  quic_span value;
  if (!quic_capsule_decode(data, &local_at, &type, &value)) return 0;
  if (type != QUIC_WTCAPSULE_TYPE_DRAIN) return 0;
  *at = local_at;
  return 1;
}
