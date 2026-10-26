#ifndef H3RESP_RESP_SIZE_H
#define H3RESP_RESP_SIZE_H

#include "app/http3/request/h3resp/resp_build.h"

/** RFC 9114 4.2.2: the size of the response field section h3resp builds --
 * each field line's name and value lengths plus 32 -- for :status, the
 * content-type (when non-null) and every extra field.
 * @param content_type the content-type value, 0 for none
 * @param extra the trailing fields
 * @return the field section size */
u64 h3resp_section_size(const char* content_type, h3resp_fields extra);

#endif
