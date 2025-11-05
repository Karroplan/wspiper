/*
 * Non-Commercial Share-Alike Software License (NCSL-1.0)
 * © 2025, Roman Gorkusha / Karroplan
 *
 * Permission is granted to use, copy, modify, and share this software
 * for non-commercial purposes only, provided that this notice and the
 * full license text are retained. Derivative works must be licensed
 * under the same terms (NCSL-1.0).
 *
 * Commercial use of this software requires a separate license agreement
 * with the author.
 *
 * SPDX-License-Identifier: NCSL-1.0
 * See the LICENSE file for full license text.
 *
 * This software uses OpenSSL 3.0, which is licensed separately under its own terms.
 * See https://www.openssl.org/source/license.html for details.
 */


#pragma once
#ifndef WSP_SOCKETS
#define WSP_SOCKETS

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct wsp_socket_t {
    int sock;
    SSL_CTX* ctx;
    SSL* ssl;

    char* hostname;

    ssize_t(*fn_read_nb)(const struct wsp_socket_t* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms);
    ssize_t(*fn_read_exact)(const struct wsp_socket_t* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms);
    ssize_t(*fn_read_expect)(const struct wsp_socket_t* sckt, void* buff, size_t buff_sz, const char* exp, int timeout_ms);
    ssize_t(*fn_write_nb)(const struct wsp_socket_t* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms);
    ssize_t(*fn_write_exact)(const struct wsp_socket_t* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms);

} wsp_socket;

//encode string to b64, no freeing needed
char* base64_encode(const unsigned char* input, int length);

// sets socket receive timeout to ms_timeout milliseconds
int set_socket_timeout(int fd, long ms_timeout);

// connects to addr within timeout_ms milliseconds
int connect_tcp_with_timeout(int sockfd, const struct sockaddr* addr, socklen_t addrlen, int timeout_ms);

// closes socket, if it's tls - closes ssl
int close_ws_socket(wsp_socket* sckt);

int is_sll_error_critical(SSL* ssl, int res);

ssize_t ssl_read_nb(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms);
ssize_t ssl_read_exact(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms);
ssize_t ssl_read_expect(const wsp_socket* sckt, void* buff, size_t buff_sz, const char* exp, int timeout_ms);

ssize_t ssl_write_nb(const wsp_socket* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms);
ssize_t ssl_write_exact(const wsp_socket* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms);



ssize_t tcp_read_nb(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms);
ssize_t tcp_read_exact(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms);
ssize_t tcp_read_expect(const wsp_socket* sckt, void* buff, size_t buff_sz, const char* exp, int timeout_ms);

ssize_t tcp_write_nb(const wsp_socket* sckt, const void* data, size_t bytes_to_write, size_t* bytes_written, int timeout_ms);
ssize_t tcp_write_exact(const wsp_socket* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms);

// sets wsp_socket function pointers to tcp implementations
void set_ws_socket_tcp(wsp_socket* sck_prms);

// sets wsp_socket function pointers to ssl/tls implementations
void set_ws_socket_tls(wsp_socket* sck_prms);

char* get_ssl_error(int err);
void ssl_wait_for_activity(SSL* ssl, int write);
int ssl_handle_io_failure(SSL* ssl, int res);
int is_sll_error_critical(SSL* ssl, int res);


#endif // WSP_SOCKETS

