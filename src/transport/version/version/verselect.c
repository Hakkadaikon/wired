#include "transport/version/version/verselect.h"

#include "transport/version/version/availfilter.h"
#include "transport/version/version/compat.h"

int verinfo_chosen_ok(u32 chosen, u32 actual_packet_version) {
  return chosen == actual_packet_version;
}

/* v appears in our supported-version list. */
static int we_list(verlist we_support, u32 v) {
  for (usz i = 0; i < we_support.n; i++)
    if (we_support.list[i] == v) return 1;
  return 0;
}

/* RFC 9368 2.3/3: a candidate is selectable if it is a usable (non-GREASE)
 * version we support and is compatible with the peer's Chosen Version. */
static int selectable(verlist we_support, u32 chosen, u32 v) {
  return verinfo_is_usable(v) && we_list(we_support, v) &&
         version_compatible(chosen, v);
}

int verinfo_pick_compatible(
    const version_information* vi, verlist we_support, u32* out) {
  for (usz i = 0; i < vi->count; i++)
    if (selectable(we_support, vi->chosen, vi->available[i])) {
      *out = vi->available[i];
      return 1;
    }
  return 0;
}
