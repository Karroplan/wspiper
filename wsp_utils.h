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

#ifndef UTILS_H
#define UTILS_H

#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>

// put thread to sleep for musec microseconds
int musleep(long);

// custom strndup implementation, because not all systems have it
char* ws_strndup(const char* src, size_t n);

// converts IP address from addrinfo to string representation
int ip_addr_to_str(const struct addrinfo* addrinfo, char* str_out, size_t str_out_len);

//sets FD in non-blocking mode
int make_fd_non_blocking(int fd);

//sets FD in blocking mode
int make_fd_blocking(int fd);

//writes exactly len bytes from buf to fd in non-blocking mode
ssize_t fd_write_exact_nb(int fd, const void* buf, size_t len);

// sends message to pipe in format: [uint64_t len][len bytes - message]
int send_message_to_pipe(int pipe_fd, const void* bytes, uint64_t bytes_num);

// chops delimiter from end of instr if present, returns newly allocated string without delimiter
// caller is responsible for freeing returned string
char* chop_delimiter(const char* instr, const char* delim, size_t* result_length);

#endif // UTILS_H