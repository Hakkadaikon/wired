#include "transport/version/version/verselect.h"

#include "transport/version/version/availfilter.h"
#include "transport/version/version/compat.h"

int quic_verinfo_chosen_ok(u32 chosen, u32 actual_packet_version) {
  return chosen == actual_packet_version;
}

/* v appears in the peer's Available Versions list. */
static int peer_lists(const quic_version_information *vi, u32 v) {
  for (usz i = 0; i < vi->count; i++)
    if (vi->available[i] == v) return 1;
  return 0;
}

/* RFC 9368 2.2/3: a candidate is selectable if it is a usable (non-GREASE)
 * version the peer lists and is compatible with the peer's Chosen Version. */
static int selectable(const quic_version_information *vi, u32 v) {
  return quic_verinfo_is_usable(v) && peer_lists(vi, v) &&
         quic_version_compatible(vi->chosen, v);
}

int quic_verinfo_pick_compatible(
    const quic_version_information *vi, quic_verlist we_support, u32 *out) {
  for (usz i = 0; i < we_support.n; i++)
    if (selectable(vi, we_support.list[i])) {
      *out = we_support.list[i];
      return 1;
    }
  return 0;
}
