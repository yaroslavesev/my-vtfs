#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/uio.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stdarg.h>
#include <linux/jiffies.h>
#include <linux/ctype.h>

#include <net/sock.h>

#include "http.h"

MODULE_LICENSE("GPL");

/* ========= logging ========= */
static int debug_http = 1; /* 0=off, 1=info, 2=debug */
module_param(debug_http, int, 0644);
MODULE_PARM_DESC(debug_http, "VTFS http debug level (0=off,1=info,2=debug)");

#define http_info(fmt, ...) do { if (debug_http >= 1) pr_info("vtfs:http: " fmt "\n", ##__VA_ARGS__); } while (0)
#define http_dbg(fmt, ...)  do { if (debug_http >= 2) pr_info("vtfs:http: [dbg] " fmt "\n", ##__VA_ARGS__); } while (0)
#define http_warn(fmt, ...) pr_warn("vtfs:http: [warn] " fmt "\n", ##__VA_ARGS__)
#define http_err(fmt, ...)  pr_err ("vtfs:http: [err] " fmt "\n", ##__VA_ARGS__)

/* module params */
static char *server_ip = "192.168.56.1";
static int server_port = 8089;

module_param(server_ip, charp, 0644);
MODULE_PARM_DESC(server_ip, "VTFS server IP");

module_param(server_port, int, 0644);
MODULE_PARM_DESC(server_port, "VTFS server port");

static int fill_request(struct kvec *vec,
                        const char *token,
                        const char *method,
                        size_t arg_size,
                        va_list args)
{
    size_t cap = 8192;
    char *buf = kzalloc(cap, GFP_KERNEL);
    size_t pos = 0;

    if (!buf)
        return -ENOMEM;

    pos += scnprintf(buf + pos, cap - pos, "GET /api/%s?token=%s", method, token);

    for (size_t i = 0; i < arg_size; i++) {
        const char *k = va_arg(args, char *);
        const char *v = va_arg(args, char *);

        if (pos >= cap) {
            kfree(buf);
            return -ENOSPC;
        }
        pos += scnprintf(buf + pos, cap - pos, "&%s=%s", k, v);
    }

    pos += scnprintf(buf + pos, cap - pos,
                     " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                     server_ip);

    if (pos >= cap) {
        kfree(buf);
        return -ENOSPC;
    }

    vec->iov_base = buf;
    vec->iov_len  = pos;
    return 0;
}

static int send_all(struct socket *sock, const char *buf, size_t len)
{
    struct msghdr msg = {0};
    size_t off = 0;

    while (off < len) {
        struct kvec v = {
            .iov_base = (void *)(buf + off),
            .iov_len  = len - off,
        };

        int ret = kernel_sendmsg(sock, &msg, &v, 1, v.iov_len);
        if (ret < 0) return ret;
        if (ret == 0) return -EPIPE;
        off += (size_t)ret;
    }
    return 0;
}

static const char *find_hdr(const char *hdrs, const char *key)
{
    return strstr(hdrs, key);
}

static int parse_content_length(const char *raw, int *out_len)
{
    const char *cl = find_hdr(raw, "Content-Length:");
    int v = -1;

    if (!cl) return -ENOENT;
    cl += strlen("Content-Length:");
    while (*cl == ' ' || *cl == '\t') cl++;

    if (!isdigit(*cl)) return -EINVAL;

    v = 0;
    while (isdigit(*cl)) {
        v = v * 10 + (*cl - '0');
        cl++;
        if (v > (1024 * 1024)) break;
    }

    *out_len = v;
    return 0;
}

static int recv_http_response(struct socket *sock, char **out, size_t *out_len)
{
    const size_t CHUNK = 4096;
    const size_t HARD_MAX = 256 * 1024;

    char *buf = NULL;
    size_t cap = 0, total = 0;
    int content_length = -1;
    char *hdr_end = NULL;

    buf = kmalloc(CHUNK + 1, GFP_KERNEL);
    if (!buf) return -ENOMEM;
    cap = CHUNK + 1;
    buf[0] = '\0';

    while (1) {
        struct msghdr msg;
        struct kvec vec;
        int ret;

        if (total + CHUNK + 1 > cap) {
            size_t new_cap = cap * 2;
            if (new_cap < total + CHUNK + 1) new_cap = total + CHUNK + 1;
            if (new_cap > HARD_MAX + 1) new_cap = HARD_MAX + 1;
            if (new_cap <= cap) { kfree(buf); return -ENOSPC; }

            buf = krealloc(buf, new_cap, GFP_KERNEL);
            if (!buf) return -ENOMEM;
            cap = new_cap;
        }

        memset(&msg, 0, sizeof(msg));
        vec.iov_base = buf + total;
        vec.iov_len  = cap - total - 1;

        ret = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, 0);
        if (ret < 0) { kfree(buf); return ret; }
        if (ret == 0) break;

        total += (size_t)ret;
        buf[total] = '\0';

        if (!hdr_end) {
            hdr_end = strstr(buf, "\r\n\r\n");
            if (hdr_end) {
                int tmp;
                if (parse_content_length(buf, &tmp) == 0) content_length = tmp;
            }
        }

        if (hdr_end && content_length >= 0) {
            size_t hdr_sz = (size_t)(hdr_end + 4 - buf);
            size_t need = hdr_sz + (size_t)content_length;
            if (total >= need) break;
        }

        if (total >= HARD_MAX) break;
    }

    *out = buf;
    *out_len = total;
    return 0;
}

static const char *skip_to_int(const char *p)
{
    while (*p && !isdigit(*p) && *p != '-') p++;
    return p;
}

static bool parse_int64_at(const char *p, int64_t *out)
{
    long long v = 0;
    int sign = 1;

    p = skip_to_int(p);
    if (!*p) return false;

    if (*p == '-') { sign = -1; p++; }
    if (!isdigit(*p)) return false;

    v = 0;
    while (isdigit(*p)) {
        v = v * 10 + (*p - '0');
        p++;
    }

    *out = (int64_t)(sign * v);
    return true;
}

static bool find_key_int64(const char *body, const char *key, int64_t *out)
{
    const char *p = strstr(body, key);
    if (!p) return false;
    p += strlen(key);
    return parse_int64_at(p, out);
}

static int64_t parse_http_response(char *raw, size_t raw_size, char *resp, size_t resp_size)
{
    char *hdr_end = strstr(raw, "\r\n\r\n");
    if (!hdr_end) return -6;
    char *body = hdr_end + 4;

    int code = 0;
    if (sscanf(raw, "HTTP/%*s %d", &code) != 1) return -6;
    if (code != 200) return -5;

    int content_length = -1;
    if (parse_content_length(raw, &content_length) != 0) return -6;
    if (content_length < 0) return -6;

    size_t hdr_size = (size_t)(body - raw);
    if (hdr_size + (size_t)content_length > raw_size) return -6;

    /* Copy body -> resp as text */
    if (resp && resp_size) {
        size_t n = min((size_t)content_length, resp_size - 1);
        memcpy(resp, body, n);
        resp[n] = '\0';
    }

    /* Determine rc */
    {
        int64_t rc = 0;

        /* common JSON keys */
        if (find_key_int64(body, "\"rc\":", &rc)) return rc;
        if (find_key_int64(body, "\"ino\":", &rc)) return rc;

        /* body might be just a number */
        if (parse_int64_at(body, &rc)) return rc;

        return 0;
    }
}

int64_t vtfs_http_call(const char *token, const char *method,
                       char *response_buffer, size_t buffer_size,
                       size_t arg_size, ...)
{
    struct socket *sock = NULL;
    struct sockaddr_in saddr;
    int error;
    int64_t ret;

    unsigned long t0 = jiffies;

    error = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (error < 0) {
        http_err("sock_create_kern failed=%d", error);
        return -1;
    }

    if (sock && sock->sk) {
        sock->sk->sk_rcvtimeo = msecs_to_jiffies(2000);
        sock->sk->sk_sndtimeo = msecs_to_jiffies(2000);
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons((u16)server_port);
    saddr.sin_addr.s_addr = in_aton(server_ip);

    error = kernel_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
    if (error < 0) {
        http_warn("connect %s:%d failed=%d", server_ip, server_port, error);
        sock_release(sock);
        return -2;
    }

    struct kvec vec;
    va_list args;
    va_start(args, arg_size);
    error = fill_request(&vec, token, method, arg_size, args);
    va_end(args);

    if (error) {
        http_err("fill_request failed=%d method=%s", error, method);
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return error;
    }

    http_dbg("send %s len=%zu", method, vec.iov_len);

    error = send_all(sock, (const char *)vec.iov_base, vec.iov_len);
    kfree(vec.iov_base);

    if (error < 0) {
        http_warn("send_all failed=%d method=%s", error, method);
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -3;
    }

    char *raw = NULL;
    size_t raw_len = 0;

    error = recv_http_response(sock, &raw, &raw_len);

    kernel_sock_shutdown(sock, SHUT_RDWR);
    sock_release(sock);

    if (error < 0) {
        http_warn("recv_http_response failed=%d method=%s", error, method);
        kfree(raw);
        return -4;
    }

    if (!raw || raw_len == 0) {
        kfree(raw);
        return -4;
    }

    ret = parse_http_response(raw, raw_len, response_buffer, buffer_size);
    kfree(raw);

    if (ret < 0) {
        http_warn("parse resp rc=%lld method=%s bytes=%zu", (long long)ret, method, raw_len);
        if (debug_http >= 2 && response_buffer) http_dbg("body: %s", response_buffer);
    } else {
        http_dbg("ok method=%s rc=%lld time_ms=%u",
                 method, (long long)ret, jiffies_to_msecs(jiffies - t0));
        if (debug_http >= 2 && response_buffer) http_dbg("body: %s", response_buffer);
    }

    return ret;
}

void encode(const char *src, char *dst)
{
    while (*src) {
        unsigned char c = (unsigned char)*src;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
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
            (c >= 'A' && c <= 'Z') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            *dst++ = (char)c;
        } else {
            sprintf(dst, "%%%02X", c);
            dst += 3;
        }
    }
    *dst = '\0';
}
