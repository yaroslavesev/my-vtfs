#pragma once
#include <linux/types.h>
#include <linux/stddef.h>

int64_t vtfs_http_call(const char *token, const char *method,
                       char *response_buffer, size_t buffer_size,
                       size_t arg_size, ...);

int64_t vtfs_http_call2(const char *token, const char *method,
                        char *response_buffer, size_t buffer_size,
                        size_t *out_payload_len,
                        size_t arg_size, ...);

void encode(const char *src, char *dst);
void encode_n(const char *src, size_t n, char *dst);
