#ifndef VTFS_HTTP_H
#define VTFS_HTTP_H

#include <linux/types.h>
#include <linux/stdarg.h>

int64_t vtfs_http_call(const char *token, const char *method,
                       char *response_buffer, size_t buffer_size,
                       size_t arg_size, ...);

// encode whole C-string
void encode(const char *src, char *dst);

// encode first n bytes (doesn't require src to be '\0'-terminated)
void encode_n(const char *src, size_t n, char *dst);

#endif // VTFS_HTTP_H
