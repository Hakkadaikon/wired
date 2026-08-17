#include "app/http3/core/h3/settings_check.h"

int h3_setting_allowed(u64 id) {
  return id < QUIC_H3_SETTING_RESERVED_LOW ||
         id > QUIC_H3_SETTING_RESERVED_HIGH;
}

int h3_setting_h3_datagram_value_ok(u64 id, u64 value) {
  return id != QUIC_H3_SETTING_H3_DATAGRAM || value <= 1;
}
