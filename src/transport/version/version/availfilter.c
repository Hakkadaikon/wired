#include "transport/version/version/availfilter.h"

#include "transport/version/version/version.h"

int verinfo_is_usable(u32 version) { return !version_is_reserved(version); }
