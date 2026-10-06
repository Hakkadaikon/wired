#ifndef WIRED_SRVRUN_HTTPX_H
#define WIRED_SRVRUN_HTTPX_H

#include "app/http3/server/srvrun/srvrun.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Small conveniences for a wired_http_handler filling its exchange. */

/**
 * Answer x with a text/plain body: sets status (0 = 200), content_type and
 * appends text to x->body (cut to what fits).
 * @param x      exchange being answered
 * @param status response status, 0 for 200
 * @param text   NUL-terminated body text
 * @return 1, so a handler can `return wired_http_reply_text(...)`
 */
int wired_http_reply_text(wired_http_exchange* x, u16 status, const char* text);

/**
 * Append the response header field name: value to x (first round only).
 * Both strings are views and must outlive the round (string literals do).
 * @param x     exchange being answered
 * @param name  lowercase field name, NUL-terminated
 * @param value field value, NUL-terminated
 * @return 1 ok, 0 if x already holds WIRED_HTTP_MAX_FIELDS fields
 */
int wired_http_add_field(
    wired_http_exchange* x, const char* name, const char* value);

#endif
