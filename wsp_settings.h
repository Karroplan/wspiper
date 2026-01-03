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


#pragma once
#ifndef WSP_SETTINGS
#define WSP_SETTINGS
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define DEF_OUT_PIPE_NAME "/tmp/wsoutpipe"
#define DEF_IN_PIPE_NAME "/tmp/wsinpipe"

typedef struct connect_endpoints_t {
    bool secure; // false - ws, true - wss
    char* hostname; //passed via
    char* path;
    char* bind_interface; // can be NULL
    uint16_t port;
    struct addrinfo* addrinf;
    struct connect_endpoints_t* next;
} connect_endpoints;

typedef struct wsp_settings_t {
    char* connection_string;
	int32_t timeout; //ms, socket read/connect timeout
    connect_endpoints* conn_endpoints;
    int32_t ping_period; // ms
    int32_t pong_timeout; // ms
	int32_t reconnect; //ms, reconnect delay if connection lost or can't connect

    bool check_server_cert;

	//bools to track if values were set via CLI and need to be freed
    char* input_pipe_name; bool binpipedef; // name of pipe to read messages to send
	char* output_pipe_name; bool boutpipedef; // name of pipe to write received messages
	char* input_pipe_message_delimiter; bool bdelimdef; //delimiter for messages in input pipe, def - \n

	uint32_t inp_pipe_timeout; // ms
	size_t max_msg_size;   // bytes
} wsp_settings;

//set default values to settings struct
void set_default_settings(wsp_settings* settings);
void free_settings(wsp_settings* settings);

// get next token from instr, using delim as delimiter
// caller must free returned string
char* ws_strgetnexttoken(const char* instr, const char* delim);

// check if url starts with ws:// or wss:// - otherwise return -1
// if secFlag != NULL - set *secFlag to true if wss://, false if ws://
int ws_urlStartsWithProperProtocol(const char* url, bool* secFlag);

// extract host from url
// caller must free returned string
// returns only hostname
// doesn't include port
// supports ipv4/ipv6 in url
// doesn't support national domain names
char* ws_getHostFromUrl(char* url);

// custom strndup implementation, because not all systems have it
char* ws_strndup(const char* src, size_t n);

// extract port from url
// returns port number or 0 if not found or error
uint16_t ws_getPortFromUrl(char* url);

//extract path from url
//caller must free returned string
char* ws_getPathFromUrl(char* url);

// convert instr to chain of connection-endpoints
// instr example:
// ws://brain4net.com:888/ui,ws://ya.ru/path1/long/,wss://8.8.8.8/very/long/path,ws://mail.ru:44555/,wss://ya.ru,https://d3.ru/,wss://[2022:BBB:88:2::1]:8866/v6/path,wss://8.8.8.8/very/long/path?with=param1&with2=param2#and_fragment
//
// 
// ret 0 - ok
// ret -1 - error
// Disclaimer: doesn't handle national domains (like .��, .���, etc)
int parse_str_to_addrs(char* instr, connect_endpoints** ppce);

int parse_str_to_addrs(char* instr, connect_endpoints** ppci);
void free_connect_endpoints(connect_endpoints* ci);

#endif // WSP_SETTINGS
