#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stdarg.h>

#include "http.h"

static char *server_ip = "192.168.56.1";
static int server_port = 8089;

module_param(server_ip, charp, 0644);
MODULE_PARM_DESC(server_ip, "VTFS server IP");
module_param(server_port, int, 0644);
MODULE_PARM_DESC(server_port, "VTFS server port");

#define REQ_BUF_MAX 4096

static int fill_request(struct kvec *vec, const char *token, const char *method,
                        size_t arg_size, va_list args)
{
    char *buf = kzalloc(REQ_BUF_MAX, GFP_KERNEL);
    size_t off = 0;
    int n;

    if (!buf)
        return -ENOMEM;

    if (!token) token = "";
    if (!method) method = "";

    n = scnprintf(buf + off, REQ_BUF_MAX - off, "GET /api/%s?token=%s", method, token);
    off += n;

    for (size_t i = 0; i < arg_size; i++) {
        const char *k = va_arg(args, char *);
        const char *v = va_arg(args, char *);
        if (!k) k = "";
        if (!v) v = "";

        n = scnprintf(buf + off, REQ_BUF_MAX - off, "&%s=%s", k, v);
        off += n;

        if (off >= REQ_BUF_MAX - 128) {
            kfree(buf);
            return -ENOSPC;
        }
    }

    n = scnprintf(buf + off, REQ_BUF_MAX - off,
                  " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", server_ip);
    off += n;

    vec->iov_base = buf;
    vec->iov_len = off;
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
        vec.iov_len = buffer_size - total;

        int ret = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, 0);
        if (ret == 0)
            break;
        if (ret < 0)
            return ret;

        total += ret;
    }

    return total;
}

static int parse_status_code(const char *raw)
{
    const char *p = strchr(raw, ' ');
    if (!p) return -EINVAL;
    p++;
    if (!p[0] || !p[1] || !p[2]) return -EINVAL;
    if (p[0] < '0' || p[0] > '9') return -EINVAL;
    if (p[1] < '0' || p[1] > '9') return -EINVAL;
    if (p[2] < '0' || p[2] > '9') return -EINVAL;
    return (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
}

static int find_content_length(const char *headers, int *out_len)
{
    const char *p = headers;
    const char *needle = "Content-Length:";
    size_t needle_len = strlen(needle);

    while (p && *p) {
        const char *line_end = strstr(p, "\r\n");
        int crlf = 1;
        if (!line_end) {
            line_end = strstr(p, "\n");
            crlf = 0;
        }
        if (!line_end) break;

        size_t line_len = (size_t)(line_end - p);

        if (line_len >= needle_len && !strncmp(p, needle, needle_len)) {
            const char *v = p + needle_len;
            while (*v == ' ' || *v == '\t') v++;
            if (kstrtoint(v, 10, out_len))
                return -EINVAL;
            return 0;
        }

        p = line_end + (crlf ? 2 : 1);
        if (*p == '\r' || *p == '\n')
            break;
    }

    return -ENOENT;
}

static int64_t parse_http_response(char *raw, size_t raw_size, char *resp, size_t resp_size)
{
    char *header_end = strstr(raw, "\r\n\r\n");
    size_t header_sep = 4;
    if (!header_end) {
        header_end = strstr(raw, "\n\n");
        header_sep = 2;
    }
    if (!header_end)
        return -6;

    int code = parse_status_code(raw);
    if (code < 0)
        return -6;
    if (code != 200)
        return -5;

    size_t headers_len = (size_t)(header_end - raw);
    char *headers = raw;
    headers[headers_len] = '\0';

    int content_length = -1;
    if (find_content_length(headers, &content_length) != 0)
        return -6;

    char *body = header_end + header_sep;
    if (!body)
        return -6;

    size_t have_body = raw_size - (size_t)(body - raw);
    if ((size_t)content_length > have_body)
        return -7;

    if (content_length < (int)sizeof(int64_t))
        return -7;

    int payload_len = content_length - (int)sizeof(int64_t);
    if ((size_t)payload_len > resp_size)
        return -ENOSPC;

    int64_t ret_val;
    memcpy(&ret_val, body, sizeof(int64_t));

    if (payload_len > 0)
        memcpy(resp, body + sizeof(int64_t), (size_t)payload_len);

    return ret_val;
}

int64_t vtfs_http_call(const char *token, const char *method,
                       char *response_buffer, size_t buffer_size,
                       size_t arg_size, ...)
{
    struct socket *sock;
    struct sockaddr_in saddr;
    int64_t ret;
    int error;

    error = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (error < 0)
        return -1;

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

    char *raw_buffer = kmalloc(buffer_size + 1024 + 1, GFP_KERNEL);
    if (!raw_buffer) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -ENOMEM;
    }
    memset(raw_buffer, 0, buffer_size + 1024 + 1);

    int read_bytes = receive_all(sock, raw_buffer, buffer_size + 1024);
    kernel_sock_shutdown(sock, SHUT_RDWR);
    sock_release(sock);

    if (read_bytes < 0) {
        kfree(raw_buffer);
        return -4;
    }

    raw_buffer[read_bytes] = '\0';
    memset(response_buffer, 0, buffer_size);

    ret = parse_http_response(raw_buffer, (size_t)read_bytes, response_buffer, buffer_size);

    kfree(raw_buffer);
    return ret;
}

void encode_n(const char *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++) {
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

void encode(const char *src, char *dst)
{
    if (!src) {
        *dst = '\0';
        return;
    }
    encode_n(src, strlen(src), dst);
}
