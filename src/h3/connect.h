#ifndef QUIC_H3_CONNECT_H
#define QUIC_H3_CONNECT_H

/* RFC 9114 4.4. A CONNECT request omits the :scheme and :path pseudo-header
 * fields and MUST include the :authority pseudo-header; :method is "CONNECT".
 * Returns 1 if the four presence flags satisfy this, 0 otherwise. */
int quic_h3_connect_ok(int has_method_connect, int has_authority,
                       int has_scheme, int has_path);

#endif
