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
#include "wsp_thrdpiperead.h"


int try_create_named_pipe_rd(const char* pipe_name)
{
	int ret_access = access(g_settings.input_pipe_name, R_OK);

	if (ret_access != 0) {
		int ret_mkfifo = mkfifo(g_settings.input_pipe_name, 0666);

		if (ret_mkfifo != 0)
			return -1;
	}

	return 0;
}

int try_open_named_pipe_read(const char* pipe_name)
{
	int fd = -1;

	if (access(pipe_name, R_OK) == -1) {
		if (mkfifo(pipe_name, 0666) == -1) {
			return -1;
		}
	}

	fd = open(pipe_name, O_RDONLY | O_NONBLOCK);
	//fd = open(pipe_name, O_RDONLY);
	if (fd == -1) return -1;

	int epfd = epoll_create1(0);
	if (epfd == -1) {
		close(fd);
		return -1;
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLHUP,
		.data.fd = fd
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {

		close(epfd);
		close(fd);
		return -1;
	}

	struct epoll_event epevctl = {
		.events = EPOLLIN,
		.data.fd = g_ctl_pipe_for_piperead[0]
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_ctl_pipe_for_piperead[0], &epevctl) == -1) {
		wsp_log(LOG_INFO, "THRDRD errno: %d", errno);
		close(epfd);
		return -1;
	}

	int n = epoll_wait(epfd, &ev, 1, -1);
	if (n > 0 && ev.events & EPOLLIN) {
		close(epfd);
		return fd;
	}

	close(fd);
	close(epfd);
	return -1;
}

/*
int try_open_named_pipe_read_nb(const char* pipe_name) {
	int fd = -1;
	fd = open(pipe_name, O_RDONLY | O_NONBLOCK);
	return fd;
}
*/

// tries to read from named pipe fd until delimiter found or buffer full - delimiter NOT included in read data
// ret -1 - fatal error, should try to close pipe and reopen it
// ret 0 - no data, should try read again
// ret >0 - bytes read
// TODO: one epoll-fd per read op - maybe optimized by reusing epoll-fd per pipe
ssize_t try_read_name_pipe_nb(int fifo_fd, char** buff, size_t buff_sz, const char* delimiter) {
	ssize_t total_read = 0;

	int epfd = epoll_create1(0);
	if (epfd == -1) {
		close(epfd);
		return -1;
	}

	struct epoll_event epev = {
		.events = EPOLLIN,
		.data.fd = fifo_fd
	};

	
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fifo_fd, &epev) == -1) {
		wsp_log(LOG_INFO, "THRDRD errno: %d", errno);
		close(epfd);
		return -1;
	}

	struct epoll_event epevctl = {
		.events = EPOLLIN,
		.data.fd = g_ctl_pipe_for_piperead[0]
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_ctl_pipe_for_piperead[0], &epevctl) == -1) {
		wsp_log(LOG_INFO, "THRDRD errno: %d", errno);
		close(epfd);
		return -1;
	}


	memset(*buff, '\0', buff_sz);

	//buff_sz -1 to leave space for null terminator
	while (total_read < (buff_sz - 1) ) { 
		char curr_char;

		int epret = epoll_wait(epfd, &epev, 1, -1); // wait indefinitely

		if (epev.data.fd == g_ctl_pipe_for_piperead[0]) { // control pipe signaled - should stop
			close(epfd);
			return -1;
		}

		if (epret == -1 && errno == EINTR) { // call interrupted by signal, calling thread should stop
			close(epfd);
			return -1;
		}


		if (epev.events & EPOLLHUP && !(epev.events & EPOLLIN)) { // writer closed pipe, but there may be data to read
			continue;
		}

		ssize_t rd = read(fifo_fd, &curr_char, 1); // read one byte at a time

		if (rd == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) { // no data to read
				close(epfd);
				return 0;
			}
			else { // fatal error
				close(epfd);
				return -1;
			}
		}

		if (rd == 0) { // EOF, writer closed pipe
			close(epfd);
			return 0; // EOF reached before reading enough bytes
		}

		(*buff)[total_read] = curr_char;
		total_read += rd;
		size_t delim_size = strlen(delimiter);

		if (total_read >= delim_size) {
			if (strncmp(&((*buff)[(size_t)total_read - delim_size]), delimiter, delim_size) == 0) {
				(*buff)[(size_t)total_read - delim_size] = '\0'; // null-terminate to be able to print
				close(epfd);
				return total_read - (ssize_t)delim_size; // read excluding delimiter
			}
		}
	}

	close(epfd);
	return -2; // buffer full, delimiter not found
}

void* thrd_piperead(void* arg) {

	// 
	// while threads_run {
	// 
	//		try access and create input pipe
	//		if failed - create it via mkfifo
	// 
	//		try open input pipe
	//		if opened {
	//			try read terminated message from it (read uses epoll on inpipe and ctl pipe)
	//			if read {
	//				put message to pipe towards socket thread (msg format: [uint32 len][len bytes - message])
	//				continue
	//			}
	//			else {
	//				close input pipe
	//				contiune
	//			}
	//		}
	//		sleep for (inp_pipe_timeout) ms // default 100ms
	// }
	// 
	// close & unlink input pipe
	// 

	wsp_log(LOG_INFO, "Thread for piperead started.");

	int inp_pipe_opened = 0;
	int inp_fifo_fd = -1;

	char* inp_buff = malloc(g_settings.max_msg_size + 1);
	if (inp_buff == NULL) {
		wsp_log(LOG_ERR, "Not enough memory for input pipe read buffer!\nThread for piperead exited.");
		send_threads_stop();
		pthread_exit(NULL);
	}

	while (g_threads_run) {

		if (!inp_pipe_opened) {

			// try open input pipe
			inp_fifo_fd = try_open_named_pipe_read(g_settings.input_pipe_name);
			if (inp_fifo_fd == -1) {
				//wsp_log(LOG_INFO, "Failed to open named pipe %s", g_settings.input_pipe_name);
				// log disabled - too spammy if writer not present
				musleep(g_settings.reconnect);

				inp_pipe_opened = 0;

				continue;
			}

			inp_pipe_opened = 1;
			wsp_log(LOG_INFO, "Named pipe %s opened.", g_settings.input_pipe_name);
			make_fd_non_blocking(inp_fifo_fd);
		}

		// opened, try to read terminated message from it
		if (inp_pipe_opened) {

			// ret -1 - fatal error, should try to close pipe and reopen it, or got SIGINT
			// ret 0 - no data, should try read again
			// ret >0 - bytes read

			// delimiter excluded in read data
			ssize_t ret_res = try_read_name_pipe_nb(inp_fifo_fd, &inp_buff, g_settings.max_msg_size, g_settings.input_pipe_message_delimiter);
			if (ret_res > 0) {
				// put message to queue towards socket thread

				wsp_log(LOG_INFO, "THRDRD: %s", inp_buff);
				send_message_to_pipe(g_pipe_read_to_sock[1], inp_buff, (uint64_t)ret_res);
				
				continue;
			}
			else if (ret_res == 0) {
				// no data, should try read again, no sleep - just loop
				continue;
			}
			else {
				// fatal error or got SIGINT, should try to close pipe and reopen it
				close(inp_fifo_fd);
				inp_pipe_opened = 0;
				wsp_log(LOG_INFO, "Closed named pipe %s due to read error.", g_settings.input_pipe_name);
				continue;
			}
		}
	}

	if (inp_buff) { free(inp_buff); inp_buff = NULL; }

	make_fd_blocking(inp_fifo_fd);
	close(inp_fifo_fd);

	// must no do unlink here - writer will continute to write to pipe after reader closed it if unlink called
	//unlink(g_settings.input_pipe_name); 

	wsp_log(LOG_INFO, "Thread for piperead finished.");

	pthread_exit(NULL);
}
