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


#define _POSIX_C_SOURCE 200809L  //nanosleep requres it
#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "wsp_globs.h"
#include "wsp_log.h"
#include "wsp_utils.h"
#include "wsp_settings.h"
#include "wsp_cli.h"
#include "wsp_thrdpiperead.h"
#include "wsp_thrdsocket.h"
#include "wsp_thrdpipewrite.h"

void signal_handler(int sig) {
	send_threads_stop();
	fprintf(stdout, "\n"); // there is ^C in term without \n
}

int setup_signals() {

	struct sigaction sa;
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL); // handle Ctrl+C
	sigaction(SIGABRT, &sa, NULL); // handle abort

	signal(SIGPIPE, SIG_IGN); // ignore SIGPIPE to avoid process termination if writing to broken pipe!

	return 0;
}

int wait_threads() {

	pthread_join(g_thrdid_socket, NULL);
	pthread_join(g_thrdid_piperead, NULL);
	pthread_join(g_thrdid_pipewrite, NULL);

	wsp_log(LOG_INFO, "Threads stopped.");

	return 0;
}

int wsp_free() {

	close(g_ctl_pipe_for_piperead[0]);
	close(g_ctl_pipe_for_piperead[1]);
	close(g_ctl_pipe_for_pipesock[0]);
	close(g_ctl_pipe_for_pipesock[1]);
	close(g_ctl_pipe_for_pipewrite[0]);
	close(g_ctl_pipe_for_pipewrite[1]);

	close(g_pipe_read_to_sock[0]);
	close(g_pipe_read_to_sock[1]);
	close(g_pipe_sock_to_write[0]);
	close(g_pipe_sock_to_write[1]);

	free_settings(&g_settings);

	return 0;
}

int start_threads() {
	pthread_attr_t attr;

	g_threads_run = 1;

	if (pthread_attr_init(&attr) != 0) {
		wsp_log(LOG_ERR, "pthread_attr_init() failed.");
		return -1;
	}

	int ret_p1 = pipe(g_ctl_pipe_for_piperead);
	int ret_p2 = pipe(g_ctl_pipe_for_pipewrite);
	int ret_p3 = pipe(g_ctl_pipe_for_pipesock);

	int ret_p4 = pipe(g_pipe_read_to_sock);
	int ret_p5 = pipe(g_pipe_sock_to_write);

	if (ret_p1 != 0 || ret_p2 != 0 || ret_p3 != 0 || ret_p4 != 0 || ret_p5 != 0) {
		wsp_log(LOG_ERR, "Internal pipes creation failed.");
		return -1;
	}

	int ret_sock = pthread_create(&g_thrdid_socket, &attr, thrd_socket, NULL);
	int ret_prd = pthread_create(&g_thrdid_piperead, &attr, thrd_piperead, NULL);
	int ret_pwr = pthread_create(&g_thrdid_pipewrite, &attr, thrd_pipewrite, NULL);
	
	if(ret_sock != 0 || ret_prd != 0 || ret_pwr != 0) {
		wsp_log(LOG_ERR, "pthread_create() failed.");
		return -1;
	}

	wsp_log(LOG_INFO, "Threads started.");
	return 0;
}

int wsp_init_settings(wsp_settings* settings, int argc, char* argv[]) {

	set_default_settings(&g_settings);
	if(get_cli_args(argc, argv, &g_settings) != 0) {
		wsp_log(LOG_ERR, "Failed to parse command line arguments.");
		return -1;
	}

	if(parse_str_to_addrs(g_settings.connection_string, &g_settings.conn_endpoints) != 0) {
		wsp_log(LOG_ERR, "Failed to parse connection string.");
		return -1;
	}

	wsp_log(LOG_INFO, "Settings:\n");
	wsp_log(LOG_INFO, "Conn str:\n%s", g_settings.connection_string);
	wsp_log(LOG_INFO, "Input pipe: %s", g_settings.input_pipe_name);
	wsp_log(LOG_INFO, "Output pipe: %s", g_settings.output_pipe_name);
	wsp_log(LOG_INFO, "Timeout: %d", g_settings.timeout);
	wsp_log(LOG_INFO, "Reconnect timeout: %d", g_settings.reconnect);
	wsp_log(LOG_INFO, "Ping period: %d", g_settings.ping_period);
	wsp_log(LOG_INFO, "Pong timeout: %d", g_settings.pong_timeout);


	return 0;
}

int main(int argc, char** argv) {

	wsp_loginit();

	if (setup_signals() != 0) {
		wsp_log(LOG_ERR, "Failed to start threads.");

		wsp_logclose();

		return EXIT_FAILURE;
	}

	if (wsp_init_settings(&g_settings, argc, argv) != 0) {
		wsp_log(LOG_ERR, "Failed to init settings.");
		wsp_logclose();
		return EXIT_FAILURE;
	}

	if (start_threads() != 0) {
		wsp_log(LOG_ERR, "Failed to start threads.");

		g_threads_run = 0;
		wait_threads();
		wsp_logclose();
		
		return EXIT_FAILURE;
	}

	//pause();
	//stop_threads();

	wait_threads();

	wsp_free();

	wsp_logclose();

	return EXIT_SUCCESS;

}
