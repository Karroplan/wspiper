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
 *
 * This software uses OpenSSL 3.0, which is licensed separately under its own terms.
 * See https://www.openssl.org/source/license.html for details.
 */


#define _POSIX_C_SOURCE 200809L //struct addrinfo requires it
#define _GNU_SOURCE
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
#include "wsp_thrdsocket.h"
#include "wsp_sockets.h"
#include "wsp_websock.h"

connect_endpoints* g_current_conn_endpoint = NULL;
struct addrinfo* g_current_addrinfo = NULL;
wsp_socket g_current_socket = { 0 };
int g_ping_timer_fd = -1;
int g_pong_timer_fd = -1;

void init_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
	EVP_cleanup();
}

int create_pingpong_timers() {
	g_ping_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (g_ping_timer_fd == -1) return -1;

	g_pong_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (g_pong_timer_fd == -1) {
		close(g_ping_timer_fd);
		g_ping_timer_fd = -1;
		g_pong_timer_fd = -1;
		return -1;
	}

	struct itimerspec timer_spec_ping = {
			.it_interval = {.tv_sec = g_settings.ping_period / 1000, .tv_nsec = (g_settings.ping_period % 1000) * 1000000 }, // interval
			.it_value = {.tv_sec = (g_settings.ping_period/2) / 1000, .tv_nsec = ((g_settings.ping_period / 2) % 1000) * 1000000 }     // frst expiration
	};

	struct itimerspec timer_spec_pong = {
		.it_interval = {.tv_sec = g_settings.pong_timeout / 1000, .tv_nsec = (g_settings.pong_timeout % 1000) * 1000000 }, // interval
		.it_value = {.tv_sec = g_settings.pong_timeout / 1000, .tv_nsec = (g_settings.pong_timeout % 1000) * 1000000 }     // frst expiration
	};

	if (timerfd_settime(g_ping_timer_fd, 0, &timer_spec_ping, NULL) == -1) {
		close(g_ping_timer_fd);
		g_ping_timer_fd = -1;
		g_pong_timer_fd = -1;
		return -1;
	}

	if (timerfd_settime(g_pong_timer_fd, 0, &timer_spec_pong, NULL) == -1) {
		close(g_ping_timer_fd);
		g_ping_timer_fd = -1;
		g_pong_timer_fd = -1;
		return -1;
	}

	return g_ping_timer_fd;
}

// check_srv_cert - true: verify server certificate, false: do not verify
SSL_CTX* ssl_create_context(bool check_srv_cert) {
	const SSL_METHOD* method = TLS_client_method();
	SSL_CTX* ctx = SSL_CTX_new(method);

	if (!ctx) {
		wsp_log(LOG_ERR, "Unable to create SSL context");
		return NULL;
	}

	if (g_settings.check_server_cert) {
		//verify server certificate
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	}
	else {
		//do't verify server certificate
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	}

	return ctx;
}

int connect_tcp(const struct sockaddr_in* addr) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(sock, (struct sockaddr*)addr, sizeof(*addr)) != 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int wsp_get_next_addrinfo() {

	if (g_settings.conn_endpoints == NULL || g_settings.conn_endpoints->addrinf == NULL) {
		wsp_log(LOG_ERR, "No connection endpoints available.");
		return -1;
	}

	if (g_current_conn_endpoint == NULL) {
		g_current_conn_endpoint = g_settings.conn_endpoints;
		g_current_addrinfo = g_current_conn_endpoint->addrinf;
	}
	else {
		if (g_current_addrinfo->ai_next != NULL) {
			g_current_addrinfo = g_current_addrinfo->ai_next;
		}
		else {
			//move to next connection endpoint
			if (g_current_conn_endpoint->next != NULL) {
				g_current_conn_endpoint = g_current_conn_endpoint->next;
			}
			else {
				g_current_conn_endpoint = g_settings.conn_endpoints; //circular
			}
			g_current_addrinfo = g_current_conn_endpoint->addrinf;
		}
	}

	return 0;
}

// opens TCP connection via given addrinfo
// uses bind_interface name to bind socket if not NULL
// on success returns connected socket fd
int connect_tcp_via_addrinf(struct addrinfo* addrinf, const char* bind_interface_name, uint16_t port, int timeout_ms) {
	int sockfd = -1;

	if (addrinf->ai_family == AF_INET) {
		((struct sockaddr_in*)addrinf->ai_addr)->sin_port = htons(port);
	}
	else if (addrinf->ai_family == AF_INET6) {
		((struct sockaddr_in6*)addrinf->ai_addr)->sin6_port = htons(port);
	}
	else {
		return -1; // Unknown AF
	}

	sockfd = socket(addrinf->ai_family, SOCK_STREAM, 0);
	if(sockfd == -1) return -1;

	if(bind_interface_name) {
		if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, bind_interface_name, strlen(bind_interface_name)) != 0) {
			wsp_log(LOG_ERR, "Failed to bind socket to interface %s: %s", bind_interface_name, strerror(errno));
			close(sockfd);
			return -1;
		}
	}

	set_socket_timeout(sockfd, timeout_ms);
	if (sockfd == -1) {
		close(sockfd);
		return -1;
	}

	if (connect_tcp_with_timeout(sockfd, addrinf->ai_addr, addrinf->ai_addrlen, timeout_ms) < 0) {
		close(sockfd);
		return -1;
	}

	return sockfd; // connected successfully
}

int connect_tls(wsp_socket* sp) {

	sp->ctx = ssl_create_context(g_settings.check_server_cert);
	sp->ssl = SSL_new(sp->ctx);
	SSL_set_fd(sp->ssl, sp->sock);

	int sslret = 0;

	//set SNI
	if (!SSL_set_tlsext_host_name(sp->ssl, sp->hostname)) {
		wsp_log(LOG_ERR, "Unable to create SSL context");
	}

	while ((sslret = SSL_connect(sp->ssl)) != 1) {
		if (ssl_handle_io_failure(sp->ssl, sslret) == 1)
			continue;

		char* errstr = get_ssl_error(sslret);
		wsp_log(LOG_ERR, "SSL_connect failed: %s", errstr);
		free(errstr);

		return -1;
	}

	if (g_settings.check_server_cert) {
		long verify_result = SSL_get_verify_result(sp->ssl);
		if (verify_result != X509_V_OK) {
			return -1;
		}
	}

	return 0;
}

// generates random Sec-WebSocket-Key
// caller 's responsibility to free returned string
char* ws_make_sec_key() {
	unsigned char random_key[16];
	srand((unsigned int)time(NULL));
	for (int i = 0; i < 16; ++i) {
		random_key[i] = (unsigned char)(rand() % 256);
	}

	char* sec_key = base64_encode(random_key, 16);
	return sec_key;
}

// performs WebSocket handshake
int ws_handshake(const wsp_socket* sck_prms, const char* host, uint16_t port, const char* path) {
	char request[1024];

	char* sec_key = ws_make_sec_key();
	if (!sec_key) return -1;

	if (port == 443 || port == 80) {
		snprintf(request, sizeof(request),
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Key: %s\r\n"
			"Sec-WebSocket-Version: 13\r\n"
			"\r\n",
			path, host, sec_key);
	}
	else {
		snprintf(request, sizeof(request),
			"GET %s HTTP/1.1\r\n"
			"Host: %s:%u\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Key: %s\r\n"
			"Sec-WebSocket-Version: 13\r\n"
			"\r\n",
			path, host, port, sec_key);

	}

	size_t bytes_num;
	size_t req_len = strlen(request);

	if (sck_prms->fn_write_exact(sck_prms, request, req_len, &bytes_num, g_settings.timeout) == -1) {
		wsp_log(LOG_ERR, "Failed to send WebSocket handshake request.");

		free(sec_key);
		return -1;
	}

	char response[4096];

	if (sck_prms->fn_read_expect(sck_prms, response, sizeof(response) - 1, "\r\n\r\n", g_settings.timeout) == -1) {
		wsp_log(LOG_ERR, "Failed to read WebSocket handshake response.");

		free(sec_key);
		return -1;
	}

	response[bytes_num] = '\0';

	// Check if got 101 Switching Protocols
	if (
		strcasestr(response, "HTTP/1.1 101") &&
		strcasestr(response, "Upgrade: websocket") &&
		strcasestr(response, "Connection: Upgrade")
		) {

		wsp_log(LOG_INFO, "WebSocket handshake successful.");

		free(sec_key);
		return 0;
	}
	else {
		wsp_log(LOG_INFO, "WebSocket handshake failed.");

		free(sec_key);
		return -1;
	}
}

// opens TCP connection via current addrinfo
// on success: if secure - setups TLS
// then performs WebSocket handshake
int open_ws_connection() {

	int tcp_socket = connect_tcp_via_addrinf(g_current_addrinfo, g_current_conn_endpoint->bind_interface, g_current_conn_endpoint->port, g_settings.timeout);
	if (tcp_socket == -1) return -1;

	g_current_socket.sock = tcp_socket;
	g_current_socket.hostname = g_current_conn_endpoint->hostname;

	make_fd_non_blocking(tcp_socket);

	if (g_current_conn_endpoint->secure) {
		// TODO: implement TLS setup
		// TODO: set function pointers for read/write via TLS

		if (connect_tls( &g_current_socket ) == -1) {
			wsp_log(LOG_INFO, "Failed to setup TLS for connection.");
			close(tcp_socket);
			return -1;
		}

		set_ws_socket_tls(&g_current_socket);
	}
	else {
		set_ws_socket_tcp(&g_current_socket);
	}

	if (ws_handshake(&g_current_socket, g_current_socket.hostname, g_current_conn_endpoint->port, g_current_conn_endpoint->path) == -1) {
		wsp_log(LOG_INFO, "Failed to perform WebSocket handshake.");
		return -1;
	}

	return 0;
}

//clears ping timer, sends ping
int on_ping_timer(wsp_socket* sckt) {

	uint64_t expirations;
	read(g_ping_timer_fd, &expirations, sizeof(expirations));

	//printf("SCK: ping sent\n");
	//wsp_log(LOG_INFO, "Sending PING to server.");
	ws_send_ping(sckt, NULL, 0, g_settings.timeout);

	return 0;
}

int reset_pong_timer() {

	struct itimerspec timer_spec_pong = {
		.it_interval = { 0 }, // interval
		.it_value = {.tv_sec = g_settings.pong_timeout / 1000, .tv_nsec = (g_settings.pong_timeout % 1000) * 1000000 }     // frst expiration
	};

	timerfd_settime(g_pong_timer_fd, 0, &timer_spec_pong, NULL);

	return 0;
}

// message in pipe from pipe read thread -> to be sent to websocket connection
int on_pipe_to_socket(wsp_socket* sckt, int in_pipe_fd) {
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

	size_t bytes_sent = 0;
	ssize_t ret = ws_send_message(sckt, msg_buf, msg_length, &bytes_sent, g_settings.timeout);

	if (ret == -1 || bytes_sent != msg_length) {
		wsp_log(LOG_ERR, "Failed to send complete message to WebSocket.");
		free(msg_buf);
		return -1;
	}

	free(msg_buf);
	return 0;
}

// reads msg from WS and writes it to pipe_out_fd:
// firstly 8bytes - length of following message, then - message body
int on_ws_sock_read(const wsp_socket* sckt, int pipe_out_fd) {

	ws_frame_header frame_hdr = { 0 };
	ws_frame_body frame_body = { 0 };
	frame_body.body_length = 0;
	frame_body.bytes = NULL;

	int ret = ws_recv_frame_header(sckt, &frame_hdr, g_settings.timeout);
	if (ret == -1)
		return -1;

	while (frame_hdr.follows != FOLLOWS_NONE) {
		
		if (frame_hdr.follows == FOLLOWS_2B_LENGTH)
			ret = ws_recv_2b_length(sckt, &frame_hdr, g_settings.timeout);

		if (frame_hdr.follows == FOLLOWS_8B_LENGTH)
			ret = ws_recv_8b_length(sckt, &frame_hdr, g_settings.timeout);

		if (frame_hdr.follows == FOLLOWS_MASK)
			ret = ws_recv_mask(sckt, &frame_hdr, g_settings.timeout);

		if (frame_hdr.follows == FOLLOWS_BODY)
			ret = ws_recv_body(sckt, &frame_hdr, &frame_body, g_settings.timeout);

		if (ret == -1)
			return -1;
	}

	//message received, send it to pipe
	if (frame_hdr.opcode == OC_TEXT || frame_hdr.opcode == OC_BIN) {
		//ws_print_body("SCK: ", &frame_body);
		
		if(pipe_out_fd != 0)
			ret = send_message_to_pipe(pipe_out_fd, frame_body.bytes, frame_body.body_length);
	}

	if (frame_hdr.opcode == OC_PING) {
		//printf("SCK: RCVD PING\n");

		ret = ws_send_pong(sckt, &frame_body, g_settings.timeout);
	}

	if (frame_hdr.opcode == OC_PONG) {
		//printf("SCK: RCVD PONG\n");
		reset_pong_timer();
	}

	if (frame_hdr.opcode == OC_CONT) {
		// not supported!
		//printf("SCK: RCVD CONT\n");
		wsp_log(LOG_ERR, "Received CONT frame. Not supported - closing connection.");
		ws_send_close(sckt, g_settings.timeout);
		return -1;
	}

	ws_free_body(&frame_body);

	if (frame_hdr.opcode == OC_CLOSE) {
		//printf("SCK: RCVD CLOSE\n");
		ws_send_close(sckt, g_settings.timeout);
		return -1;
	}

	if(ret == -1) return -1;
	return 0;
}


void run_polling_loop(wsp_socket* sckt) {

	int epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd == -1) {
		wsp_log(LOG_ERR, "Failed to create epoll instance.");
		return;
	}

	// add socket to epoll
	struct epoll_event epevsock;
	epevsock.data.fd = sckt->sock;
	epevsock.events = EPOLLIN;

	if(epoll_ctl(epfd, EPOLL_CTL_ADD, sckt->sock, &epevsock) == -1) {
		wsp_log(LOG_ERR, "Failed to add socket to epoll.");
		close(epfd);
		return;
	}

	//add ctl_pipe to epoll
	struct epoll_event epevctl = {
		.events = EPOLLIN,
		.data.fd = g_ctl_pipe_for_pipesock[0]
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_ctl_pipe_for_pipesock[0], &epevctl) == -1) {
		wsp_log(LOG_ERR, "Failed to add ctl pipe to epoll.");
		close(epfd);
		return;
	}

	//add ping timer
	struct epoll_event epevpingtimer = {
		.events = EPOLLIN,
		.data.fd = g_ping_timer_fd
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_ping_timer_fd, &epevpingtimer) == -1) {
		wsp_log(LOG_ERR, "Failed to add ping timer to epoll.");
		close(epfd);
		return;
	}

	//add pong timer
	struct epoll_event epevpongtimer = {
		.events = EPOLLIN,
		.data.fd = g_pong_timer_fd
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_pong_timer_fd, &epevpongtimer) == -1) {
		wsp_log(LOG_ERR, "Failed to add pong timer to epoll.");
		close(epfd);
		return;
	}

	//add pipe from piperead thread
	struct epoll_event epevpipefromreadthrd = {
		.events = EPOLLIN,
		.data.fd = g_pipe_read_to_sock[0]
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_pipe_read_to_sock[0], &epevpipefromreadthrd) == -1) {
		wsp_log(LOG_ERR, "Failed to add internal pipe from readthrd.");
		close(epfd);
		return;
	}



	struct epoll_event epevnt[1];
	int epoll_timeout = -1; //wait indefinitely

	while (g_threads_run) {

		int epret = epoll_wait(epfd, epevnt, 1, epoll_timeout);
		if (epret < 0) break;

		// ctl pipe signaled - exit polling loop, will break on while condition
		if(epevnt->data.fd == g_ctl_pipe_for_pipesock[0])
			continue;
		
		// socket is ready to read
		if(epevnt->data.fd == sckt->sock) {
			if (on_ws_sock_read(sckt, g_pipe_sock_to_write[1]) == -1) {
				wsp_log(LOG_INFO, "Error reading from WebSocket or connection closed.");
				break;
			}
		}

		// pipe from piperead thread signaled - read message and send to socket
		if(epevnt->data.fd == g_pipe_read_to_sock[0]) {
			if (on_pipe_to_socket(sckt, g_pipe_read_to_sock[0]) == -1) {
				wsp_log(LOG_INFO, "Error reading from internal pipe to socket.");
				break;
			}
		}

		// ping timer fired, need to send ping
		if(epevnt->data.fd == g_ping_timer_fd) {
			on_ping_timer(sckt);
		}

		// pong timer fired, reset connection
		if (epevnt->data.fd == g_pong_timer_fd) {
			wsp_log(LOG_INFO, "Pong timeout! Connection closed.");
			ws_send_close(sckt, g_settings.timeout);
			break;
		}
	}

	close(epfd);
	return;
}

void* thrd_socket(void* arg) {

	wsp_log(LOG_INFO, "Thread for socket started.");

	// while threads_run {
	// 
	//		current_conn_endpoint = get next from list (circular)
	//		try to connect to current_conn_endpoint (with timeout)
	// 
	//		if connected {
	//			run epoll wait loop for -	socket,
	//									websocket ping timer,
	//									websocket pong timeout timer,
	//										ctl_pipe,
	//										pipe from piperead thread
	//				
	//			if read from sock {
	//				put message to pipe towards pipewrite thread (msg format: [uint32 len][len bytes - message])
	//			}
	//			if read from ctl_pipe {
	//				continue // will break on while condition
	//			}
	//			if read from pipe from piperead thread {
	//				send message to socket
	//			}
	//		}
	//		sleep for (reconnect) ms // default 100ms
	// }
	// 
	// close socket & pipe from piperead thread

	init_openssl();

	if (create_pingpong_timers() == -1) {
		wsp_log(LOG_ERR, "Failed to setup ping-pong timers.");

		send_threads_stop();

		cleanup_openssl();

		return NULL;
	}

	while (g_threads_run) {

		// moves pointers to next addrinfo to try
		if (wsp_get_next_addrinfo() != 0) {
			//failed getting next addrinfo -> stop working
			wsp_log(LOG_ERR, "Failed to get next addrinfo for connection.");
			g_threads_run = 0;
			break;
		}

		char ipaddr[INET6_ADDRSTRLEN];
		ip_addr_to_str(g_current_addrinfo, ipaddr, sizeof(ipaddr) - 1);
		wsp_log(LOG_INFO, "Trying to connect to %s%s via %s:%d",
			(g_current_conn_endpoint->secure?"wss://":"ws://"),
				g_current_conn_endpoint->hostname,
					ipaddr,
						g_current_conn_endpoint->port);

		int conn_ret = open_ws_connection();

		if (conn_ret == 0) {
			// connected
			wsp_log(LOG_INFO, "Connection successful");

			run_polling_loop(&g_current_socket); // if it quits, connection is closed or there was an error

			wsp_log(LOG_INFO, "Connection closed");

			close_ws_socket(&g_current_socket);
		} else {
			wsp_log(LOG_INFO, "Connection failed");
			close_ws_socket(&g_current_socket);
		}

		musleep(g_settings.reconnect * 1000);
	}

	cleanup_openssl();

	wsp_log(LOG_INFO, "Thread for socket finished.");

	return NULL;
}

