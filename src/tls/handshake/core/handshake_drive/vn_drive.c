#include "tls/handshake/core/handshake_drive/vn_drive.h"
#include "transport/version/version/version.h"

/* Read the i-th offered version (4 big-endian bytes) from the VN list. */
static u32 vn_at(const u8 *vn_versions, usz i)
{
    const u8 *p = vn_versions + i * 4;
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
           ((u32)p[2] << 8) | (u32)p[3];
}

/* True if want appears verbatim in the VN list. */
static int vn_lists(const u8 *vn_versions, usz n_versions, u32 want)
{
    for (usz i = 0; i < n_versions; i++)
        if (vn_at(vn_versions, i) == want) return 1;
    return 0;
}

/* True if want is offered in the VN list and is not a reserved/GREASE value. */
static int vn_offers(const u8 *vn_versions, usz n_versions, u32 want)
{
    if (quic_version_is_reserved(want)) return 0;
    return vn_lists(vn_versions, n_versions, want);
}

int quic_vn_choose(const u8 *vn_versions, usz n_versions,
                   const u32 *my_versions, usz my_count, u32 *chosen)
{
    for (usz i = 0; i < my_count; i++) {
        if (!vn_offers(vn_versions, n_versions, my_versions[i])) continue;
        *chosen = my_versions[i];
        return 1;
    }
    return 0;
}

int quic_vn_acceptable(int handshake_started)
{
    return handshake_started == 0;
}
