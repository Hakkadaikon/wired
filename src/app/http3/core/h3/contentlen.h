#ifndef H3_CONTENTLEN_H
#define H3_CONTENTLEN_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1.2. A request or response with a Content-Length header must
 * carry exactly that many DATA payload bytes; a mismatch is a malformed
 * message (H3_MESSAGE_ERROR). */

/* 1 if the bytes actually received equal the declared Content-Length. */
int h3_content_length_ok(u64 declared, u64 actual);

/* 1 if the bytes received so far already exceed the declared Content-Length
 * (a violation detectable before the body completes). */
int h3_content_length_exceeded(u64 declared, u64 received_so_far);

#endif
