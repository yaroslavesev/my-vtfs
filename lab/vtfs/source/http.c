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

#include <net/sock.h>   // sock->sk timeouts

#include "http.h"

MODULE_LICENSE("GPL");

// module params (can be passed to insmod)
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
        if (ret == 0) break;      // EOF
        if (ret < 0) return ret;  // error

        total += ret;
    }
    return total;
}

static const char *find_hdr(const char *hdrs, const char *key)
{
    // very simple case-sensitive search (server is predictable for this lab)
    return strstr(hdrs, key);
}

static int64_t parse_http_response(char *raw, size_t raw_size, char *resp, size_t resp_size)
{
    // find header/body split
    char *hdr_end = strstr(raw, "\r\n\r\n");
    if (!hdr_end) return -6;
    char *body = hdr_end + 4;

    // status code
    int code = 0;
    if (sscanf(raw, "HTTP/%*s %d", &code) != 1) return -6;
    if (code != 200) return -5;

    // Content-Length
    int content_length = -1;
    {
        const char *cl = find_hdr(raw, "Content-Length:");
        if (cl) {
            cl += strlen("Content-Length:");
            while (*cl == ' ') cl++;
            if (kstrtoint(cl, 10, &content_length))
                return -6;
        }
    }

    if (content_length < 0) return -6;

    // sanity: do we have the body fully in raw?
    size_t hdr_size = (size_t)(body - raw);
    if (hdr_size + (size_t)content_length > raw_size) return -6;

    if (content_length < (int)sizeof(int64_t)) return -7;

    int64_t rc;
    memcpy(&rc, body, sizeof(int64_t));

    int payload_len = content_length - (int)sizeof(int64_t);
    if (payload_len < 0) payload_len = 0;

    if ((size_t)payload_len > resp_size) return -ENOSPC;

    memcpy(resp, body + sizeof(int64_t), (size_t)payload_len);
    return rc;
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

    error = send_all(sock, (const char *)vec.iov_base, vec.iov_len);
    kfree(vec.iov_base);

    if (error < 0) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -3;
    }

    char *raw = kmalloc(buffer_size + 2048, GFP_KERNEL);
    if (!raw) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -ENOMEM;
    }

    int read_bytes = receive_all(sock, raw, buffer_size + 2048);
    kernel_sock_shutdown(sock, SHUT_RDWR);
    sock_release(sock);

    if (read_bytes < 0) {
        kfree(raw);
        return -4;
    }

    ret = parse_http_response(raw, (size_t)read_bytes, response_buffer, buffer_size);
    kfree(raw);
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
