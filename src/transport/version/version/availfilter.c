#include "transport/version/version/availfilter.h"
#include "transport/version/version/version.h"

int quic_verinfo_is_usable(u32 version)
{
    return !quic_version_is_reserved(version);
}
