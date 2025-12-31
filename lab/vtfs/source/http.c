#include "http.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/string.h>

static char *server_ip = "192.168.56.1";
static int server_port = 8089;

module_param(server_ip, charp, 0444);
MODULE_PARM_DESC(server_ip, "VTFS server IPv4 address");
module_param(server_port, int, 0444);
MODULE_PARM_DESC(server_port, "VTFS server TCP port");

static int fill_request(struct kvec *vec,
                        const char *token,
                        const char *method,
                        size_t arg_size,
                        va_list args)
{
    /* Запрос строим как строку. Под твой API (GET /api/<method>?token=...&k=v...) */
    size_t cap = 8192;
    char *req = kzalloc(cap, GFP_KERNEL);
    if (!req) return -ENOMEM;

    /* Простейшая "append" без overflow: держим pos */
    size_t pos = 0;
    int n = 0;

#define APPEND_FMT(...) do { \
        n = scnprintf(req + pos, cap - pos, __VA_ARGS__); \
        if (n < 0 || (size_t)n >= cap - pos) { kfree(req); return -ENOSPC; } \
        pos += (size_t)n; \
    } while (0)

    APPEND_FMT("GET /api/%s?token=%s", method, token);

    for (size_t i = 0; i < arg_size; i++) {
        const char *k = va_arg(args, const char *);
        const char *v = va_arg(args, const char *);
        APPEND_FMT("&%s=%s", k, v);
    }

    APPEND_FMT(" HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", server_ip);

#undef APPEND_FMT

    vec->iov_base = req;
    vec->iov_len  = pos;
    return 0;
}

static int receive_all(struct socket *sock, char *buffer, size_t buffer_size)
{
    struct msghdr msg;
    struct kvec vec;
    int total = 0;

    while (total < (int)buffer_size) {
        memset(&msg, 0, sizeof(msg));
        vec.iov_base = buffer + total;
        vec.iov_len  = buffer_size - (size_t)total;

        int ret = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, 0);
        if (ret == 0) break;     /* EOF */
        if (ret < 0) return ret; /* error */
        total += ret;
    }
    return total;
}

static int find_status_code(const char *raw, int raw_size)
{
    /* ожидаем "HTTP/1.1 200" */
    const char *p = raw;
    const char *end = raw + raw_size;
    const char *line_end = memchr(p, '\n', end - p);
    if (!line_end) return -6;

    /* вытащим код */
    /* ищем пробел, затем ещё пробел */
    const char *sp1 = memchr(p, ' ', line_end - p);
    if (!sp1) return -6;
    const char *sp2 = memchr(sp1 + 1, ' ', line_end - (sp1 + 1));
    if (!sp2) return -6;

    if (sp2 - (sp1 + 1) < 3) return -6;

    char code[4] = {0};
    memcpy(code, sp1 + 1, 3);
    return simple_strtol(code, NULL, 10);
}

static int find_content_length(const char *hdr, int hdr_size)
{
    const char *p = hdr;
    const char *end = hdr + hdr_size;

    while (p < end) {
        const char *line_end = memchr(p, '\n', end - p);
        if (!line_end) break;

        /* пустая строка? (конец заголовков) */
        if ((line_end == p) || (line_end == p + 1 && *p == '\r')) break;

        if (!strncasecmp(p, "Content-Length:", 15)) {
            const char *q = p + 15;
            while (q < line_end && (*q == ' ' || *q == '\t')) q++;
            return simple_strtol(q, NULL, 10);
        }

        p = line_end + 1;
    }
    return -1;
}

static int64_t parse_http_response(char *raw, int raw_size,
                                   char *resp, size_t resp_size)
{
    int code = find_status_code(raw, raw_size);
    if (code != 200) return -5;

    /* найти \r\n\r\n */
    char *body = NULL;
    for (int i = 0; i + 3 < raw_size; i++) {
        if (raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n') {
            body = raw + i + 4;
            break;
        }
    }
    if (!body) return -6;

    int hdr_size = (int)(body - raw);
    int content_length = find_content_length(raw, hdr_size);
    if (content_length < 0) return -6;

    if (content_length < (int)sizeof(int64_t)) return -7;

    int body_avail = raw_size - hdr_size;
    if (content_length > body_avail) return -6;

    int payload_len = content_length - (int)sizeof(int64_t);
    if ((size_t)payload_len > resp_size) return -ENOSPC;

    int64_t ret_val;
    memcpy(&ret_val, body, sizeof(int64_t));
    memcpy(resp, body + sizeof(int64_t), payload_len);

    return ret_val;
}

int64_t vtfs_http_call(const char *token, const char *method,
                       char *response_buffer, size_t buffer_size,
                       size_t arg_size, ...)
{
    struct socket *sock = NULL;
    struct sockaddr_in saddr;
    int error;
    int64_t ret;

    error = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (error < 0) return -1;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons((u16)server_port);
    saddr.sin_addr.s_addr = in_aton(server_ip);

    error = kernel_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
    if (error < 0) {
        sock_release(sock);
        return -2;
    }

    struct kvec vec;
    va_list args;
    va_start(args, arg_size);
    error = fill_request(&vec, token, method, arg_size, args);
    va_end(args);

    if (error) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return error;
    }

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    error = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
    kfree(vec.iov_base);

    if (error < 0) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -3;
    }

    size_t raw_cap = buffer_size + 4096; /* запас под заголовки */
    char *raw = kmalloc(raw_cap, GFP_KERNEL);
    if (!raw) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -ENOMEM;
    }

    int read_bytes = receive_all(sock, raw, raw_cap);

    kernel_sock_shutdown(sock, SHUT_RDWR);
    sock_release(sock);

    if (read_bytes < 0) {
        kfree(raw);
        return -4;
    }

    ret = parse_http_response(raw, read_bytes, response_buffer, buffer_size);
    kfree(raw);
    return ret;
}

/* URL-encode: safe chars = [0-9a-zA-Z], остальное -> %XX */
void encode(const char *src, char *dst)
{
    while (*src) {
        unsigned char c = (unsigned char)*src;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z')) {
            *dst++ = (char)c;
        } else {
            sprintf(dst, "%%%02X", c);
            dst += 3;
        }
        src++;
    }
    *dst = '\0';
}

void encode_n(const char *src, size_t n, char *dst)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z')) {
            *dst++ = (char)c;
        } else {
            sprintf(dst, "%%%02X", c);
            dst += 3;
        }
    }
    *dst = '\0';
}
