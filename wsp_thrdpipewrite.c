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
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
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
#include "wsp_thrdpipewrite.h"

int try_create_named_pipe_wr(const char* pipe_name)
{
	int ret_access = access(g_settings.input_pipe_name, W_OK);

	if (ret_access != 0) {
		int ret_mkfifo = mkfifo(g_settings.input_pipe_name, 0666);

		if (ret_mkfifo != 0)
			return -1;
	}

	return 0;
}

int try_open_named_pipe_wr(const char* pipe_name) {
	int fd = -1;
	fd = open(pipe_name, O_WRONLY);
	return fd;
}

int try_open_named_pipe_write(const char* pipe_name)
{
	int fd = -1;

	if (access(pipe_name, F_OK) == -1) {
		if (mkfifo(pipe_name, 0666) == -1) {
			return -1;
		}
	}

	fd = open(pipe_name, O_WRONLY | O_NONBLOCK);
	if (fd == -1) return -1;

	int epfd = epoll_create1(0);
	if (epfd == -1) {
		close(fd);
		return -1;
	}

	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLHUP,
		.data.fd = fd
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		close(epfd);
		close(fd);
		return -1;
	}

	int n = epoll_wait(epfd, &ev, 1, 0);
	if (n > 0 && ev.events & EPOLLOUT) {
		close(epfd);
		return fd;
	}

	close(epfd);
	close(fd);
	return -1;
}


int create_epollfd(int out_pipe_fd) {

	int epfd = epoll_create1(0);
	if (epfd == -1) return -1;

	// add ctl pipe to epoll
	struct epoll_event epevctl = {
		.events = EPOLLIN,
		.data.fd = g_ctl_pipe_for_pipewrite[0]
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_ctl_pipe_for_pipewrite[0], &epevctl) == -1) {
		wsp_log(LOG_ERR, "Failed to add ctl pipe to epoll in pipewrite thread.");
		close(epfd);
		return -1;
	}

	// add pipe from socket to epoll
	struct epoll_event epevpipefromsock = {
		.events = EPOLLIN,
		.data.fd = g_pipe_sock_to_write[0]
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_pipe_sock_to_write[0], &epevpipefromsock) == -1) {
		wsp_log(LOG_ERR, "Failed to add pipe from socket to epoll in pipewrite thread.");
		close(epfd);
		return -1;
	}

	//add output named pipe
	struct epoll_event epevoutpipe = {
		.events = EPOLLIN,
		.data.fd = out_pipe_fd
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, out_pipe_fd, &epevoutpipe) == -1) {
		wsp_log(LOG_ERR, "Failed to add pipe from socket to epoll in pipewrite thread.");
		close(epfd);
		return -1;
	}

	return epfd;
}

int on_event_pipe(int in_pipe_fd, int out_pipe_fd) {

	uint64_t msg_length = 0;
	ssize_t retb = read(in_pipe_fd, &msg_length, sizeof(msg_length));
	if (retb != sizeof(msg_length)) {
		wsp_log(LOG_ERR, "Failed to read message length from pipe.");
		return -1;
	}

	char* msg_buf = (char*)malloc(msg_length + 1); // +1 for null terminator
	if (msg_buf == NULL) {
		wsp_log(LOG_ERR, "Failed to allocate memory for message buffer.");
		return -1;
	}

	retb = read(in_pipe_fd, msg_buf, msg_length);
	if (retb != (ssize_t)msg_length) {
		wsp_log(LOG_ERR, "Failed to read complete message from pipe.");
		free(msg_buf);
		return -1;
	}
	msg_buf[msg_length] = '\0'; // null terminate the message

	//TODO: send message to named pipe_out
	wsp_log(LOG_INFO, "PWR: %s", msg_buf);
	ssize_t retw = write(out_pipe_fd, msg_buf, msg_length);
	ssize_t retdl = write(out_pipe_fd, g_settings.input_pipe_message_delimiter, strlen(g_settings.input_pipe_message_delimiter)); // write newline as delimiter

	if (retw != (ssize_t)msg_length || retdl != strlen(g_settings.input_pipe_message_delimiter)) {
		wsp_log(LOG_ERR, "Failed to write complete message to output pipe.");
		free(msg_buf);
		return -1;
	}

	free(msg_buf);
	return 0;
}

int run_pipewrite_polling_loop(int epfd, int out_pipe_fd) {
	struct epoll_event epev;

	while (g_threads_run) {
		int epret = epoll_wait(epfd, &epev, 1, -1);
		if (epret < 0) break;

		if (epev.data.fd == g_ctl_pipe_for_pipewrite[0]) {
			break;
		}

		if (epev.data.fd == g_pipe_sock_to_write[0]) {
			on_event_pipe(g_pipe_sock_to_write[0], out_pipe_fd);
		}
	}

	return 0;
}

void* thrd_pipewrite(void* arg) {

	// while threads_run {
	//		try access and create output named pipe
	//		try open output pipe
	//		while(threads_run) {
	//			poll pipe from_socket_to_write and ctl pipe
	//			if ctl pipe - break
	//			if pipe from_socket_to_write - read message length, read message
	//				if named pipe opened write message to output pipe
	//		}
	//		close output pipe
	// }

	wsp_log(LOG_INFO, "Thread for pipewrite started.");
	int out_pipe_fd = -1;

	while (g_threads_run) {

		/*
		if (!wr_pipe_opened) {
			if (try_create_named_pipe_wr(g_settings.output_pipe_name) != 0) {
				wr_pipe_opened = 0;
				//wsp_log(LOG_INFO, "Failed to create named pipe %s", g_settings.output_pipe_name);
				musleep(g_settings.reconnect);
				continue;
			}

			out_pipe_fd = try_open_named_pipe_wr(g_settings.output_pipe_name);
			if (out_pipe_fd == -1) {
				wr_pipe_opened = 0;
				//wsp_log(LOG_INFO, "Failed to open named pipe %s for writing", g_settings.output_pipe_name);
				musleep(g_settings.reconnect);
				continue;
			}

			wr_pipe_opened = 1;
			wsp_log(LOG_INFO, "Named pipe %s opened for writing", g_settings.output_pipe_name);
		}
		*/

		if (out_pipe_fd == -1) {
			out_pipe_fd = try_open_named_pipe_write(g_settings.output_pipe_name);

			if (out_pipe_fd == -1) {
				musleep(g_settings.reconnect);
				continue;
			}

			wsp_log(LOG_INFO, "Named pipe %s opened for writing", g_settings.output_pipe_name);
		}

		int epfd = create_epollfd(out_pipe_fd);
		if (epfd == -1) {
			wsp_log(LOG_ERR, "Failed to create epoll fd in pipewrite thread.");
			send_threads_stop();
			continue;
		}
		
		run_pipewrite_polling_loop(epfd, out_pipe_fd);

		close(epfd);
	}

	if (out_pipe_fd != -1) {
		close(out_pipe_fd);
		unlink(g_settings.output_pipe_name);
	}

	wsp_log(LOG_INFO, "Thread for pipewrite finished.");

	pthread_exit(NULL);
}
