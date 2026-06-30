#include "transport/version/version/vneg.h"

void quic_vneg_init(quic_vneg *v, const u32 *supported, usz n)
{
    v->phase = QUIC_VNEG_INITIAL;
    v->negotiated = 0;
    v->reacted = 0;
    v->n_supported = n;
    for (usz i = 0; i < n; i++) v->supported[i] = supported[i];
}

/* Linear membership over a version list. */
static int list_has(const u32 *list, usz n, u32 version)
{
    for (usz i = 0; i < n; i++)
        if (list[i] == version) return 1;
    return 0;
}

int quic_vneg_supports(const quic_vneg *v, u32 version)
{
    return list_has(v->supported, v->n_supported, version);
}

/* The version_information passes the downgrade checks: Chosen equals the
 * version in use, Available is non-empty, and Chosen is in Available. */
static int downgrade_ok(const quic_version_info *vi, u32 in_use)
{
    if (vi->chosen != in_use || vi->n_available == 0) return 0;
    return list_has(vi->available, vi->n_available, vi->chosen);
}

int quic_vneg_check_downgrade(quic_vneg *v, const quic_version_info *vi,
                              u32 in_use)
{
    if (downgrade_ok(vi, in_use)) return 1;
    v->phase = QUIC_VNEG_ERROR;
    return 0;
}

/* A version qualifies if it is one we support and is not our original. */
static int qualifies(const quic_vneg *v, u32 original, u32 ver)
{
    return ver != original && quic_vneg_supports(v, ver);
}

/* Choose the first qualifying offered version. Returns 1 with *chosen set. */
static int pick_mutual(const quic_vneg *v, u32 original,
                       const u32 *offered, usz n, u32 *chosen)
{
    for (usz i = 0; i < n; i++)
        if (qualifies(v, original, offered[i])) { *chosen = offered[i]; return 1; }
    return 0;
}

/* We may react to a VN only if we have not reacted before and it does not
 * list our original version (RFC 9368 4). */
static int may_react(const quic_vneg *v, u32 original,
                     const u32 *offered, usz n)
{
    return !v->reacted && !list_has(offered, n, original);
}

int quic_vneg_react(quic_vneg *v, u32 original, const u32 *offered, usz n,
                    u32 *chosen)
{
    if (!may_react(v, original, offered, n)) return 0;
    if (!pick_mutual(v, original, offered, n, chosen)) return 0;
    v->reacted = 1;
    v->phase = QUIC_VNEG_REACTED;
    return 1;
}

void quic_vneg_confirm(quic_vneg *v, u32 version)
{
    if (v->phase == QUIC_VNEG_ERROR) return; /* errors do not confirm */
    v->phase = QUIC_VNEG_CONFIRMED;
    v->negotiated = version;
}
