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

/*
 * Make server configurable without recompiling:
 *   sudo insmod vtfs.ko server_ip=192.168.56.1 server_port=8089
 */
static char *server_ip = "192.168.56.1";
static int server_port = 8089;

module_param(server_ip, charp, 0644);
MODULE_PARM_DESC(server_ip, "VTFS server IP");
module_param(server_port, int, 0644);
MODULE_PARM_DESC(server_port, "VTFS server port");

#define REQ_BUF_MAX 4096

// builds HTTP request into vec
static int fill_request(struct kvec *vec, const char *token, const char *method,
                        size_t arg_size, va_list args)
{
    char *buf = kzalloc(REQ_BUF_MAX, GFP_KERNEL);
    size_t off = 0;
    int n;

    if (!buf) return -ENOMEM;

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
            return -ENOSPC; // request too large
        }
    }

    n = scnprintf(buf + off, REQ_BUF_MAX - off,
                  " HTTP/1.1\r\nHost:%s\r\nConnection: close\r\n\r\n", server_ip);
    off += n;

    vec->iov_base = buf;
    vec->iov_len = off;
    return 0;
}

// read whole response
static int receive_all(struct socket *sock, char *buffer, size_t buffer_size)
{
    struct msghdr msg;
    struct kvec vec;
    int total = 0;

    while (total < buffer_size) {
        memset(&msg, 0, sizeof(msg));
        vec.iov_base = buffer + total;
        vec.iov_len = buffer_size - total;

        int ret = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, 0);
        if (ret == 0) break; // EOF
        if (ret < 0) return ret;

        total += ret;
    }

    return total;
}

// parse HTTP response. returns int64 ret_val from body; copies payload to resp (NOT null-terminated)
static int64_t parse_http_response(char *raw, size_t raw_size, char *resp, size_t resp_size)
{
    char *p = raw;
    char *line;
    char *status_str;
    int content_length = -1;

    // Status line
    line = strsep(&p, "\r\n");
    if (!line) return -6;

    // "HTTP/1.1 200 OK"
    (void)strsep(&line, " ");          // HTTP/1.1
    status_str = strsep(&line, " ");   // 200
    if (!status_str) return -6;

    if (strcmp(status_str, "200") != 0)
        return -5;

    // Headers
    while (p && *p) {
        line = strsep(&p, "\r\n");
        if (!line) return -6;
        if (line[0] == '\0') break; // end headers

        if (!strncmp(line, "Content-Length: ", 16)) {
            if (kstrtoint(line + 16, 0, &content_length))
                return -6;
        }
    }

    if (content_length < (int)sizeof(int64_t)) return -7;
    if (!p) return -6;

    // Body: [8 bytes ret][payload]
    if ((size_t)content_length > raw_size) {
        // not fatal, but likely incomplete read
        // continue with what we have
    }

    if (content_length - (int)sizeof(int64_t) > (int)resp_size)
        return -ENOSPC;

    int64_t ret_val;
    memcpy(&ret_val, p, sizeof(int64_t));
    p += sizeof(int64_t);

    int payload_len = content_length - (int)sizeof(int64_t);
    if (payload_len > 0) {
        memcpy(resp, p, payload_len);
    }

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

    // +1 for '\0' so strsep works safely
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

    raw_buffer[read_bytes] = '\0'; // ensure terminated
    ret = parse_http_response(raw_buffer, (size_t)read_bytes, response_buffer, buffer_size);
    kfree(raw_buffer);
    return ret;
}

/*
 * URL-encode bytes:
 * - keep [0-9a-zA-Z] as is
 * - everything else -> %XX
 */
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
    if (!src) { *dst = '\0'; return; }
    encode_n(src, strlen(src), dst);
}
