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

#include "http.h"

MODULE_LICENSE("GPL");

// module params (can be passed to insmod)
static char *server_ip = "192.168.56.1";
static int server_port = 8089;

module_param(server_ip, charp, 0644);
MODULE_PARM_DESC(server_ip, "VTFS server IP");

module_param(server_port, int, 0644);
MODULE_PARM_DESC(server_port, "VTFS server port");

static int fill_request(struct kvec *vec, const char *token, const char *method,
                        size_t arg_size, va_list args)
{
    // enough for URL + headers
    char *request_buffer = kzalloc(4096, GFP_KERNEL);
    if (!request_buffer)
        return -ENOMEM;

    strcpy(request_buffer, "GET /api/");
    strcat(request_buffer, method);
    strcat(request_buffer, "?token=");
    strcat(request_buffer, token);

    for (size_t i = 0; i < arg_size; i++) {
        const char *k = va_arg(args, char *);
        const char *v = va_arg(args, char *);
        strcat(request_buffer, "&");
        strcat(request_buffer, k);
        strcat(request_buffer, "=");
        strcat(request_buffer, v);
    }

    strcat(request_buffer, " HTTP/1.1\r\nHost: ");
    strcat(request_buffer, server_ip);
    strcat(request_buffer, "\r\nConnection: close\r\n\r\n");

    vec->iov_base = request_buffer;
    vec->iov_len  = strlen(request_buffer);
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
        vec.iov_len  = buffer_size - total;

        int ret = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, 0);
        if (ret == 0) break;      // EOF
        if (ret < 0) return ret;  // error

        total += ret;
    }
    return total;
}

static int64_t parse_http_response(char *raw, size_t raw_size, char *resp, size_t resp_size)
{
    char *p = raw;
    char *line;
    char *status;
    int content_length = -1;

    // status line
    line = strsep(&p, "\r\n");
    if (!line) return -6;

    (void)strsep(&line, " ");      // HTTP/1.1
    status = strsep(&line, " ");   // 200
    if (!status) return -6;

    if (strcmp(status, "200") != 0)
        return -5;

    // headers
    while (p && *p) {
        line = strsep(&p, "\r\n");
        if (!line) return -6;
        if (line[0] == '\0') break; // end of headers

        if (!strncmp(line, "Content-Length: ", 16)) {
            if (kstrtoint(line + 16, 0, &content_length))
                return -6;
        }
    }

    if (!p) return -6;

    // body: [int64_t rc][payload...]
    if (content_length < (int)sizeof(int64_t))
        return -7;

    content_length -= sizeof(int64_t);
    if (content_length > (int)resp_size)
        return -ENOSPC;

    int64_t rc;
    memcpy(&rc, p, sizeof(int64_t));
    p += sizeof(int64_t);

    if (p + content_length > raw + raw_size)
        return -6;

    memcpy(resp, p, content_length);
    return rc;
}

int64_t vtfs_http_call(const char *token, const char *method,
                       char *response_buffer, size_t buffer_size,
                       size_t arg_size, ...)
{
    struct socket *sock;
    struct sockaddr_in saddr;
    int error;
    int64_t ret;

    error = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (error < 0) return -1;

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

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    error = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
    kfree(vec.iov_base);

    if (error < 0) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -3;
    }

    char *raw = kmalloc(buffer_size + 1024, GFP_KERNEL);
    if (!raw) {
        kernel_sock_shutdown(sock, SHUT_RDWR);
        sock_release(sock);
        return -ENOMEM;
    }

    int read_bytes = receive_all(sock, raw, buffer_size + 1024);
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
