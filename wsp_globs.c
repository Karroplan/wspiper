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


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "wsp_globs.h"


// global flag to control threads' run state. 1 - threads should run, 0 - should stop
uint32_t g_threads_run = 1;

pthread_t g_thrdid_socket;
pthread_t g_thrdid_piperead;
pthread_t g_thrdid_pipewrite;

wsp_settings g_settings = {
	.input_pipe_message_delimiter = "\n",
	.max_msg_size = 4096, // bytes
	.inp_pipe_timeout = 100, // ms
	.input_pipe_name = "/tmp/wspinpipe",
	.output_pipe_name = "/tmp/wspoutpipe"
};

// contol pipes to wake up threads blocked on epoll_wait
int g_ctl_pipe_for_piperead[2];
int g_ctl_pipe_for_pipewrite[2];
int g_ctl_pipe_for_pipesock[2];

// pipes to pass messages between threads. Messge format { uint64_t len; byte message[len] }
int g_pipe_sock_to_write[2];
int g_pipe_read_to_sock[2];

void send_threads_stop() {
	g_threads_run = 0;

	write(g_ctl_pipe_for_piperead[1], "X", 1);
	write(g_ctl_pipe_for_pipewrite[1], "X", 1);
	write(g_ctl_pipe_for_pipesock[1], "X", 1);
}