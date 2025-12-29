#ifndef VTFS_HTTP_H
#define VTFS_HTTP_H

#include <linux/types.h>
#include <linux/stddef.h>

int64_t vtfs_http_call(const char *token, const char *method,
                       char *response_buffer, size_t buffer_size,
                       size_t arg_size, ...);

/*
 * URL-encode null-terminated string
 * (wrapper over encode_n)
 */
void encode(const char *src, char *dst);

/*
 * URL-encode arbitrary bytes (supports 0x00 too)
 * dst must be at least (3*len + 1)
 */
void encode_n(const char *src, size_t len, char *dst);

#endif // VTFS_HTTP_H
