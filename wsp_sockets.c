/*
 * Non-Commercial Share-Alike Software License (NCSL-1.0)
 * � 2025, Roman Gorkusha / Karroplan
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


#define _POSIX_C_SOURCE 200809L //struct addrinfo requires it

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <sys/timerfd.h>

#include "wsp_globs.h"
#include "wsp_log.h"
#include "wsp_utils.h"
#include "wsp_sockets.h"

//encode string to b64, no freeing needed
char* base64_encode(const unsigned char* input, int length) {
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;

    const BIO_METHOD* bfb = BIO_f_base64();
    b64 = BIO_new(bfb);
    if (!b64) return NULL;

    const BIO_METHOD* bsm = BIO_s_mem();
    bmem = BIO_new(bsm);
    if (!bmem) {
        BIO_free_all(b64);
        return NULL;
    }

    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // no string wrap
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char* buff = (char*)malloc(bptr->length + 1);
    if (!buff) {
        BIO_free_all(b64);
        return NULL;
    }
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);
    return buff;
}


//caller 's responsibility to free returned string
char* get_ssl_error(int err) {

    char* buf = malloc(1024);

    if (err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL) {
        unsigned long e;
        while ((e = ERR_get_error()) != 0) {

            ERR_error_string_n(e, buf, sizeof(buf));

        }
    }
    else if (err == SSL_ERROR_ZERO_RETURN) {
        sprintf(buf, "SSL connection closed cleanly (SSL_ERROR_ZERO_RETURN)\n");
    }
    else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        sprintf(buf, "SSL wants read or write (non-fatal)\n");
    }
    else {
        sprintf(buf, "Unhandled SSL error: %d\n", err);
    }

    return buf;
}


void ssl_wait_for_activity(SSL* ssl, int write)
{
    fd_set fds;
    int width, sock;

    sock = SSL_get_fd(ssl);

    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    width = sock + 1;

    if (write)
        select(width, NULL, &fds, NULL, NULL);
    else
        select(width, &fds, NULL, NULL, NULL);
}

int ssl_handle_io_failure(SSL* ssl, int res)
{
    switch (SSL_get_error(ssl, res)) {
    case SSL_ERROR_WANT_READ:
        /* Temporary failure. Wait until we can read and try again */
        ssl_wait_for_activity(ssl, 0);
        return 1;

    case SSL_ERROR_WANT_WRITE:
        /* Temporary failure. Wait until we can write and try again */
        ssl_wait_for_activity(ssl, 1);
        return 1;

    case SSL_ERROR_ZERO_RETURN:
        /* EOF */
        return 0;

    case SSL_ERROR_SYSCALL:
        return -1;

    case SSL_ERROR_SSL:
        /*
        * If the failure is due to a verification error we can get more
        * information about it from SSL_get_verify_result().
        */
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            wsp_log(LOG_ERR, "SSL verification error: %s",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));

        return -1;

    default:
        return -1;
    }
}


int is_sll_error_critical(SSL* ssl, int res) {
    int sslerr = SSL_get_error(ssl, res);
    switch (sslerr) {
    case SSL_ERROR_WANT_READ:
        /* Temporary failure. Wait until we can read and try again */
        return 1;

    case SSL_ERROR_WANT_WRITE:
        /* Temporary failure. Wait until we can write and try again */
        return 1;

    case SSL_ERROR_ZERO_RETURN:
        /* EOF */
        return 0;

    case SSL_ERROR_SYSCALL:
        return -1;

    case SSL_ERROR_SSL:
        char* errstr = get_ssl_error(sslerr);
        wsp_log(LOG_ERR, "SSL error: %s", errstr);
        free(errstr);
        return -1;

    default:
        return -1;
    }
}

// sets socket receive timeout to ms_timeout milliseconds
int set_socket_timeout(int fd, long ms_timeout) {
    struct timeval tv;
    tv.tv_sec = ms_timeout / 1000;
    tv.tv_usec = (ms_timeout % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }

    return 0;
}

int connect_tcp_with_timeout(int sockfd, const struct sockaddr* addr, socklen_t addrlen, int timeout_ms) {
	// set non-blocking mode
	if (make_fd_non_blocking(sockfd)) {
		return -1;
	}

	// connect non-blocking, if EINPROGRESS - it's ok, have to wait
	int ret = connect(sockfd, addr, addrlen);
	if (ret < 0 && errno != EINPROGRESS) {
		return -1;
	}

	// create epoll instance
	int epfd = epoll_create1(0);
	if (epfd < 0) {
		return -1;
	}

	// add socket to epoll
	struct epoll_event ev = { 0 };
	ev.events = EPOLLOUT;
	ev.data.fd = sockfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
		close(epfd);
		return -1;
	}

	// wait for event
	struct epoll_event events[1];

	ret = epoll_wait(epfd, events, 1, timeout_ms);

	// clean up epoll
	close(epfd);

	if (ret <= 0) {
		return -1;
	}

	// check if really connected
	int so_error;
	socklen_t len = sizeof(so_error);
	if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
		return -1;
	}

	if (so_error != 0) {
		return -1;
	}

	return 0;
}




ssize_t tcp_read_nb(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms) {

    int epfdrd = epoll_create1(0);
    if (epfdrd == -1)
        return -1;

    struct epoll_event ev;
    ev.data.fd = sckt->sock;
    ev.events = EPOLLIN;

    if (epoll_ctl(epfdrd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
        close(epfdrd);
        return -1;
    }

    int nfds = epoll_wait(epfdrd, &ev, 1, timeout_ms);
    if (nfds < 0) {
        close(epfdrd);
        return -1;
    }

    ssize_t rdbytes = recv(sckt->sock, buff, buff_sz, 0);
    close(epfdrd);

    if (rdbytes == 0)
        return -1; // EOF

    return rdbytes;
}

ssize_t tcp_read_exact(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms) {
    ssize_t total_read = 0;

    while (total_read < buff_sz) {
        ssize_t ret = 0;
        size_t rd = 0;
        ret = tcp_read_nb(sckt, buff + total_read, buff_sz - (size_t)total_read, &rd, timeout_ms);
        if (ret == -1)
            return -1;

        total_read += rd;
    }

    *bytes_read = (size_t)total_read;
    return total_read;
}

ssize_t tcp_read_expect(const wsp_socket* sckt, void* buff, size_t buff_sz, const char* expect, int timeout_ms) {
    memset(buff, 0, buff_sz);

    size_t total_read = 0;

    memset(buff, 0, buff_sz);
    char* str = (char*)buff;

    while (total_read < buff_sz - 1) {
        size_t btsread = 0;
        btsread = (size_t)tcp_read_nb(sckt, str + total_read, 1, &btsread, timeout_ms);
        if (btsread == -1) return -1;

        total_read += btsread;

        if (strstr(buff, expect))
            return (ssize_t)total_read;
    }

    return -1;
}

ssize_t tcp_write_nb(const wsp_socket* sckt, const void* data, size_t bytes_to_write, size_t* bytes_written, int timeout_ms) {

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        return -1;
    }

    struct epoll_event ev = {
        .events = EPOLLOUT,
        .data.fd = sckt->sock
    };

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sckt->sock, &ev) < 0) {
        perror("epoll_ctl");
        close(epfd);
        return -1;
    }

    ssize_t total_sent = 0;
    const char* buf = (const char*)data;

    while (total_sent < bytes_to_write) {
        int nfds = epoll_wait(epfd, &ev, 1, timeout_ms);
        if (nfds <= 0) {
            // error or timeout
            break;
        }

        if (ev.events & EPOLLOUT) {
            ssize_t n = send(sckt->sock, buf + total_sent, bytes_to_write - (size_t)total_sent, 0);
            if (n > 0) {
                total_sent += n;
            }
            else if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // socket became unready, should call epoll_wait again
                continue;
            }
            else {
                break;
            }
        }
    }

    close(epfd);
    *bytes_written = (size_t)total_sent;
    return total_sent > 0 ? total_sent : -1;
}

ssize_t tcp_write_exact(const wsp_socket* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms) {
    size_t written;
    ssize_t ret = tcp_write_nb(sckt, buff, bytes_to_write, &written, timeout_ms);

    *bytes_written = written;
    return ret;
}


ssize_t ssl_read_nb(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms) {
    int epfdrd = epoll_create1(0);
    if (epfdrd == -1)
        return -1;

    struct epoll_event ev;
    ev.data.fd = sckt->sock;
    ev.events = EPOLLIN;

    if (epoll_ctl(epfdrd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
        close(epfdrd);
        return -1;
    }

    size_t rdbytes = 0;
    bool reading = true;


    while (reading) {

        int rdret = SSL_read_ex(sckt->ssl, buff, buff_sz, &rdbytes);
        if (rdret <= 0) {
            switch (is_sll_error_critical(sckt->ssl, 0)) {
                // epoll-wait and continue
            case 1: {
                struct epoll_event events[1];

                int nfds = epoll_wait(epfdrd, events, 1, timeout_ms);
                if (nfds < 0) reading = false;

                continue;
            }
            case 0: //EOF
                reading = false;
                continue;
            case -1:
                reading = false;
                continue;
            default:
                reading = false;
                continue;
            }
        }
        else {
            close(epfdrd);
            *bytes_read = rdbytes;

            return (ssize_t)rdbytes;
        }
    }

    close(epfdrd);
    *bytes_read = rdbytes;

    return -1;
}

ssize_t ssl_read_exact(const wsp_socket* sckt, void* buff, size_t buff_sz, size_t* bytes_read, int timeout_ms) {
    size_t total_read = 0;

    while (total_read < buff_sz) {
        size_t rd = 0;
        if (ssl_read_nb(sckt, buff + total_read, buff_sz - total_read, &rd, timeout_ms) == -1) return -1;
        total_read += rd;
    }

	*bytes_read = (size_t)total_read;

    return (ssize_t)total_read;
}

ssize_t ssl_read_expect(const wsp_socket* sckt, void* buff, size_t buff_sz, const char* expect, int timeout_ms) {

    memset(buff, 0, buff_sz);

    size_t total_read = 0;

    while (total_read < buff_sz - 1) {
        size_t btsread = 0;
        btsread = (size_t)ssl_read_nb(sckt, buff + total_read, 1, &btsread, timeout_ms);
        if (btsread == -1) return -1;

        total_read += btsread;

        if (strstr(buff, expect))
            return (ssize_t)total_read;
    }

    return -1;
}


ssize_t ssl_write_nb(const wsp_socket* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms) {

    int epfdrd = epoll_create1(0);
    if (epfdrd == -1)
        return -1;

    struct epoll_event ev;
    ev.data.fd = sckt->sock;
    ev.events = EPOLLOUT;

    if (epoll_ctl(epfdrd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
        close(epfdrd);
        return -1;
    }

    size_t wrbytes = 0;
    bool writing = true;


    while (writing) {

        int wret = SSL_write_ex(sckt->ssl, buff, bytes_to_write, &wrbytes);

        if (wret <= 0) {
            switch (is_sll_error_critical(sckt->ssl, 0)) {
                // epoll-wait and continue
            case 1: {
                struct epoll_event events[1];

                int nfds = epoll_wait(epfdrd, events, 1, timeout_ms);
                if (nfds < 0) writing = false;

                continue;
            }
            case 0: //EOF
                writing = false;
                continue;
            case -1:
                writing = false;
                continue;
            default:
                writing = false;
                continue;
            }
        }
        else {
            close(epfdrd);
            *bytes_written = wrbytes;

            return (ssize_t)wrbytes;
        }
    }

    close(epfdrd);
    *bytes_written = wrbytes;

    return -1;
}

ssize_t ssl_write_exact(const wsp_socket* sckt, const void* buff, size_t bytes_to_write, size_t* bytes_written, int timeout_ms) {
    size_t total_written = 0;

    while (total_written < bytes_to_write) {
        size_t wr = 0;
        if (ssl_write_nb(sckt, buff + total_written, bytes_to_write - total_written, &wr, timeout_ms) == -1) return -1;
        total_written += wr;
    }

    *bytes_written = (size_t)total_written;
    return (ssize_t)total_written;
}


// closes socket, if it's tls - closes ssl
int close_ws_socket(wsp_socket* sckt) {
    if (sckt->ssl) {
        SSL_shutdown(sckt->ssl);
        SSL_free(sckt->ssl);
        sckt->ssl = NULL;
    }

    if (sckt->sock != -1 && sckt->sock != 0) {
        close(sckt->sock);
        sckt->sock = -1;
    }

    return 0;
}

void set_ws_socket_tcp(wsp_socket* sck_prms) {
    sck_prms->fn_read_exact = &tcp_read_exact;
    sck_prms->fn_read_expect = &tcp_read_expect;
    sck_prms->fn_read_nb = &tcp_read_nb;
    sck_prms->fn_write_exact = &tcp_write_exact;
    sck_prms->fn_write_nb = &tcp_write_nb;
}

void set_ws_socket_tls(wsp_socket* sck_prms) {
    sck_prms->fn_read_exact = &ssl_read_exact;
    sck_prms->fn_read_expect = &ssl_read_expect;
    sck_prms->fn_read_nb = &ssl_read_nb;
    sck_prms->fn_write_exact = &ssl_write_exact;
    sck_prms->fn_write_nb = &ssl_write_nb;
}
