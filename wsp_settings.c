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


#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include "wsp_settings.h"

void set_default_settings(wsp_settings* settings) {
    settings->connection_string = NULL;
    settings->conn_endpoints = NULL;
    settings->timeout = 1000; //ms
    settings->ping_period = 1000; //ms
    settings->pong_timeout = 3000; //ms
    settings->check_server_cert = true;
    settings->reconnect = 1000; //ms
	settings->output_pipe_name = DEF_OUT_PIPE_NAME; settings->boutpipedef = true;
	settings->input_pipe_name = DEF_IN_PIPE_NAME; settings->binpipedef = true;
	settings->input_pipe_message_delimiter = "\n"; settings->bdelimdef = true;
    settings->inp_pipe_timeout = 100; // ms
    settings->max_msg_size = 65536; // bytes
}

void free_settings(wsp_settings* settings) {

    if (settings->connection_string != NULL) {
        free(settings->connection_string);
		settings->connection_string = NULL;
    }

    if (!settings->binpipedef && settings->input_pipe_name != NULL) {
		free(settings->input_pipe_name);
		settings->input_pipe_name = NULL;
    }

    if (!settings->boutpipedef && settings->output_pipe_name != NULL) {
        free(settings->output_pipe_name);
        settings->output_pipe_name = NULL;
    }

    if(!settings->bdelimdef && settings->input_pipe_message_delimiter != NULL) {
        free(settings->input_pipe_message_delimiter);
        settings->input_pipe_message_delimiter = NULL;
	}
    
    if (settings->conn_endpoints != NULL) {
        free_connect_endpoints(settings->conn_endpoints);
        settings->conn_endpoints = NULL;
    }
}

void free_connect_endpoints(connect_endpoints* ci) {

    while (ci) {
        connect_endpoints* curr_ci = ci;
        ci = curr_ci->next;

        free(curr_ci->hostname);
        free(curr_ci->path);

        if (!curr_ci->addrinf->ai_next) free(curr_ci->addrinf);
        else freeaddrinfo(curr_ci->addrinf);

        free(curr_ci);
    }

}

// get next token from instr, using delim as delimiter
// caller must free returned string
char* ws_strgetnexttoken(const char* instr, const char* delim) {
    static char* savestr = NULL;
    static char* str = NULL;

    if (instr == NULL || delim == NULL) return NULL;

    if (savestr != instr) {
        savestr = (char*)instr;
        str = savestr;
    }

    // Skip leading delimiters
    while (*str && strchr(delim, *str)) {
        str++;
    }

    // delimiter not found till end of string
    if (*str == '\0') return NULL;

    // Find the end of the token
    char* end = str;
    while (*end && !strchr(delim, *end)) {
        end++;
    }

    // Allocate memory for the token
    size_t token_len =(size_t) (end - str);
    char* token = (char*)malloc(token_len + 1);
    if (!token) return NULL;

    strncpy(token, str, token_len);
    token[token_len] = '\0';

    str = ++end;

    return token;
}

// check if url starts with ws:// or wss:// - otherwise return -1
// if secFlag != NULL - set *secFlag to true if wss://, false if ws://
int ws_urlStartsWithProperProtocol(const char* url, bool* secFlag) {
    if (url == NULL) return -1;

    if (strncmp(url, "ws://", 5) == 0) {
        if (secFlag)
            *secFlag = false;
        return 0;
    }
    if (strncmp(url, "wss://", 6) == 0) {
        if (secFlag)
            *secFlag = true;
        return 0;
    }

    return -1;
}

// extract host from url
// caller must free returned string
// returns only hostname
// doesn't include port
// supports ipv4/ipv6 in url
// doesn't support national domain names
char* ws_getHostFromUrl(char* url) {
    if (!url) return NULL;

    char* scheme_end = strstr(url, "://");
    if (!scheme_end) return NULL;

    char* start = scheme_end + 3;

    // find an end of an authority part in url: first occurance / ? # or \0
    char* auth_end = start;
    while (*auth_end && *auth_end != '/' && *auth_end != '?' && *auth_end != '#') {
        auth_end++;
    }

    // Get host from [start, auth_end)
    size_t len;
    char* host_start, * host_end;

    //check if ipv6 - starts with [
    if (*start == '[') {
        host_start = start + 1;
        host_end = strchr(host_start, ']');
        if (!host_end || host_end >= auth_end) return NULL; // invalid IPv6
        len = (size_t) (host_end - host_start);
    }
    else {
        // find first from [start, auth_end)
        char* colon = strchr(start, ':');
        if (colon && colon < auth_end) {
            host_end = colon;
        }
        else {
            host_end = auth_end;
        }
        host_start = start;
        len = (size_t)(host_end - host_start);
    }

    if (len == 0) return NULL;

    char* host = (char*)malloc(len + 1);
    if (!host) return NULL;

    memcpy(host, host_start, len);
    host[len] = '\0';

    return host;
}

// extract port from url
// returns port number or 0 if not found or error
uint16_t ws_getPortFromUrl(char* url) {
    if (!url) return 0;

    char* scheme_end = strstr(url, "://");
    if (!scheme_end) return 0;

    char* start = scheme_end + 3;

    char* auth_end = start;
    while (*auth_end && *auth_end != '/' && *auth_end != '?' && *auth_end != '#') {
        auth_end++;
    }

    char* host_end;
    char* port_start;
    if (*start == '[') {
        // IPv6
        char* host_start = start + 1;
        host_end = strchr(host_start, ']');
        if (!host_end || host_end >= auth_end) return 0;

        // Port after ]
        port_start = host_end + 1;
        if (port_start >= auth_end || *port_start != ':') return 0;
        port_start++; // after :
    }
    else {
        // ipv4 or hostname
        host_end = strchr(start, ':');
        if (!host_end) return 0; // no port
        // Port after :
        port_start = host_end + 1;
        if (port_start >= auth_end) return 0;
    }

    // parse port number

    char* port_string = ws_strndup(port_start, (size_t) (auth_end - port_start));
    if (!port_string) return 0;


    char* endptr;
    long port = strtol(port_string, &endptr, 10);
    if (endptr == port_string || *endptr != '\0' || port < 0 || port > 65535) {
        free(port_string);
        return 0; // invalid port number
    }

    free(port_string);
    return (uint16_t)port;
}

//extract path from url
//caller must free returned string
char* ws_getPathFromUrl(char* url) {
    if (!url) return NULL;

    char* scheme_end = strstr(url, "://");
    if (!scheme_end) return NULL;

    char* start = scheme_end + 3;

    // find end of the  authority: first occurance / ? # or \0
    char* auth_end = start;
    while (*auth_end && *auth_end != '/' && *auth_end != '?' && *auth_end != '#') {
        auth_end++;
    }

    // if no / or found ?/#, then path is /
    if (*auth_end != '/') return strdup("/");

    // path from auth_end to end of url
    size_t len = strlen(auth_end);
    char* path = (char*)malloc(len + 1);
    if (!path) return NULL;

    memcpy(path, auth_end, len + 1);

    return path;
}

// v2
// 
// 
// convert instr to chain of connection-endpoints
// instr example:
// ws://brain4net.com:888/ui,ws://ya.ru/path1/long/,wss://8.8.8.8/very/long/path,ws://mail.ru:44555/,wss://ya.ru,https://d3.ru/,wss://[2022:BBB:88:2::1]:8866/v6/path,wss://8.8.8.8/very/long/path?with=param1&with2=param2#and_fragment
//
// 
// ret 0 - ok
// ret -1 - error
// Disclaimer: doesn't handle national domains (like .��, .���, etc)
int parse_str_to_addrs(char* instr, connect_endpoints** ppce) {

    connect_endpoints* start_ce = NULL;
    connect_endpoints** pcurr_ce = NULL;
    char* curr_url = NULL;

    if (instr == NULL || strlen(instr) == 0) return -1;

    while ((curr_url = ws_strgetnexttoken(instr, ",")) != NULL) {

        connect_endpoints* curr_connendp = NULL;
        curr_connendp = (connect_endpoints*)malloc(sizeof(connect_endpoints));
        if (!curr_connendp) {
            if (curr_url) free(curr_url);
            return -1;
        }

        curr_connendp->next = NULL;
        curr_connendp->path = NULL;
        curr_connendp->addrinf = NULL;
        curr_connendp->hostname = NULL;

        //check if curr_url starts with ws:// or wss:// and set secure flag
        if (ws_urlStartsWithProperProtocol(curr_url, &curr_connendp->secure) == 0) {

            char* host = ws_getHostFromUrl(curr_url);

            if (host) {

                curr_connendp->hostname = host;

                curr_connendp->port = ws_getPortFromUrl(curr_url);
                if (curr_connendp->port == 0) {
                    if (curr_connendp->secure) curr_connendp->port = 443;
                    else curr_connendp->port = 80;
                }

                //path may be NULL
                curr_connendp->path = ws_getPathFromUrl(curr_url);

                struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
                getaddrinfo(host, NULL, &hints, &curr_connendp->addrinf);

                if (curr_connendp->addrinf) {
                    //all info got successfully - store it and continue to next url
                    if (!start_ce) {
                        start_ce = curr_connendp;
                        pcurr_ce = &start_ce->next;
                    }
                    else {
                        *pcurr_ce = curr_connendp;
                        pcurr_ce = &curr_connendp->next;
                    }

                    continue;
                }

                // addrinfo failed - free and continue
                free(host);
            }
        }

        //check ws/wss failed - free and continue
        free(curr_connendp);
        free(curr_url);
    }

    *ppce = start_ce;

    if (!start_ce) return -1;

    return 0;
}
