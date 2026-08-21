#include "transport/version/version/v2keys.h"

#include "common/bytes/util/bytes.h"

/* RFC 9001 5.2 v1 Initial salt. */
static const u8 V1_SALT[INITIAL_SALT_LEN] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

/* RFC 9369 3.3.1 v2 Initial salt. */
static const u8 V2_SALT[INITIAL_SALT_LEN] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

static const u8* salt_for(u32 version) {
  if (version == VERSION_1) return V1_SALT;
  if (version == VERSION_2) return V2_SALT;
  return 0;
}

int version_initial_salt(u32 version, const u8** salt, usz* len) {
  const u8* s = salt_for(version);
  if (!s) return 0;
  *salt = s;
  *len  = INITIAL_SALT_LEN;
  return 1;
}

usz version_quic_label(u8* buf, u32 version, const char* suffix, usz sfx_len) {
  const char* prefix;
  usz         prefix_len;
  if (!version_label_prefix(version, &prefix, &prefix_len))
    version_label_prefix(VERSION_1, &prefix, &prefix_len);
  bytes_memcpy(buf, prefix, prefix_len);
  bytes_memcpy(buf + prefix_len, suffix, sfx_len);
  return prefix_len + sfx_len;
}

int version_label_prefix(u32 version, const char** prefix, usz* len) {
  if (version == VERSION_1) {
    *prefix = "quic ";
    *len    = 5;
    return 1;
  }
  if (version == VERSION_2) {
    *prefix = "quicv2 ";
    *len    = 7;
    return 1;
  }
  return 0;
}
