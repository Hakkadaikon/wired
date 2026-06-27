#include "h3/connect.h"

/* CONNECT requires :method == CONNECT and :authority. */
static int connect_required(int has_method_connect, int has_authority)
{
    return has_method_connect && has_authority;
}

/* CONNECT forbids :scheme and :path. */
static int connect_forbidden(int has_scheme, int has_path)
{
    return has_scheme || has_path;
}

int quic_h3_connect_ok(int has_method_connect, int has_authority,
                       int has_scheme, int has_path)
{
    if (!connect_required(has_method_connect, has_authority)) return 0;
    if (connect_forbidden(has_scheme, has_path)) return 0;
    return 1;
}
