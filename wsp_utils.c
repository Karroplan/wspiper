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


#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdbool.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <dirent.h>

#include "wsp_utils.h"


// put thread to sleep for musec microseconds
int musleep(long musec) {
    struct timespec req;

    req.tv_sec = musec / 1000000;
    req.tv_nsec = (musec % 1000000) * 1000;

    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
        //do nothing - sleep interrupted by signal
    }

    return 0;
}

// custom strndup implementation, because not all systems have it
char* ws_strndup(const char* src, size_t n) {
    if (!src)
        return NULL;

    size_t len = strnlen(src, n);
    char* dst = (char*)malloc(len + 1);
    if (!dst)
        return NULL;

    memcpy(dst, src, len);
    dst[len] = '\0';

    return dst;
}


int ip_addr_to_str(const struct addrinfo* addrinfo, char* str_out, size_t str_out_len) {
    void* addr_ptr = NULL;

    if (addrinfo == NULL || str_out == NULL) {
        return -1;
    }

    if (addrinfo->ai_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)addrinfo->ai_addr;
        addr_ptr = &(ipv4->sin_addr);
    }
    else if (addrinfo->ai_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addrinfo->ai_addr;
        addr_ptr = &(ipv6->sin6_addr);
    }
    else {
        return -2; // Unsupported address family
    }

    if (inet_ntop(addrinfo->ai_family, addr_ptr, str_out, (unsigned int)str_out_len) == NULL) {
        perror("inet_ntop");
        return -3;
    }

    return 0;
}

//sets FD in non-blocking mode
int make_fd_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int make_fd_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

//writes exactly len bytes from buf to fd in non-blocking mode
ssize_t fd_write_exact_nb(int fd, const void* buf, size_t len) {

    size_t total_written = 0;

    int epfd = epoll_create1(0);
    if (epfd == -1) {
        return -1;
    }

    struct epoll_event ev = {
        .events = EPOLLOUT | EPOLLHUP,
        .data.fd = fd
    };

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        close(epfd);
        return -1;
    }

    while (total_written < len) {

        int epret = epoll_wait(epfd, &ev, 1, 0);
        if (epret == -1 || ev.events & EPOLLHUP) {
            close(epfd);
            return -1;
        }

        if (epret == 0) continue;

        ssize_t written = write(fd, (const char*)buf + total_written, len - total_written);
        if (written == -1) {
            close(epfd);
            return -1; // error occurred
        }
        else if (written == 0) {
            close(epfd);
            return -1; // EOF reached - pipe closed
        }
        total_written += (size_t)written;
    }

    close(epfd);
    return (ssize_t)total_written;
}

// sends message to pipe in format:
//// firstly 8bytes - length of following message, then - message body
int send_message_to_pipe(int pipe_fd, const void* bytes, uint64_t bytes_num) {

    //write 8 bytes - length of following message
    ssize_t ret = fd_write_exact_nb(pipe_fd, &bytes_num, sizeof(uint64_t));
    if (ret == -1) return -1;

    //write message body
    ret = fd_write_exact_nb(pipe_fd, bytes, bytes_num);
    if (ret == -1) return -1;

    return 0;
}

//chop_delimiter(inp_buff, g_settings.input_pipe_message_delimiter);
// return NULL on delim not found
// result_length includes termingating \0
char* chop_delimiter(const char* instr, const char* delim, size_t* result_length) {

    size_t instr_len = strlen(instr);
    size_t delim_len = strlen(delim);
    if (instr_len < delim_len) {
        *result_length = 0;
        return NULL; // delimiter longer than input string
    }

    if (strncmp(&instr[instr_len - delim_len], delim, delim_len) != 0) {
        *result_length = 0;
        return NULL; // delimiter not found at the end
    }

	//delimiter found at the end, create new string without it
    size_t result_len = instr_len - delim_len;
    char* inp_buff = (char*)malloc(result_len + 1); // +1 for null terminator
    if (inp_buff == NULL) {
        *result_length = 0;
        return NULL; // memory allocation failed
    }
    strncpy(inp_buff, instr, result_len);
	inp_buff[result_len] = '\0'; // null-terminate the result string
	
    *result_length = result_len + 1;
    return inp_buff;
}