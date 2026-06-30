#include "transport/version/versmgr/v2switch.h"

#include "transport/version/version/v2keys.h"
#include "transport/version/version/version.h"

int quic_vers_is_v2(u32 version) {
  return version == QUIC_VERSION_2; /* RFC 9369 3 */
}

int quic_vers_initial_salt(u32 version, const u8 **salt, usz *salt_len) {
  return quic_version_initial_salt(version, salt, salt_len);
}

int quic_vers_label_prefix(u32 version, const char **prefix, usz *len) {
  return quic_version_label_prefix(version, prefix, len);
}
