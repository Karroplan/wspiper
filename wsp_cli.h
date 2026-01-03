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
#ifndef WSP_CLI
#define WSP_CLI

// command line options:
// -c <URI-list>, --connect <URI-list> - URI list to connect to
// URI list is: <URL1>,<URL2>,<URL3>,...
// each URL on format <proto>://<host>[:<port>][path]
// where:
// <proto> - ws(for websocket over http) or wss(for websocket over https)
// <host> - FQDN (will be resolved) or IPv4 address or [IPv6] (rfc requires ipv6 in square brackets)
// <port> (not required) - tcp port num. if ommitted wss uses - 443  and ws - 80
// <path> - URL path
// 
// example:
// ws://brain4net.com:888/ui,ws://ya.ru/path1/long/,wss://8.8.8.8/very/long/path,ws://mail.ru:44555/,wss://ya.ru,https://d3.ru/,wss://[2022:BBB:88:2::1]:8866/v6/path
// https://d3.ru/ in above will be silently skipped due to unknown proto. Have to be ws|wss
// 
// 
// -t, --timeout - timeout for WS-session setup, ms, default - 1000(1sec) - session setup timeout, socket read timeout
// -r, --reconnect - reconnect WS-session period, ms, default - 1000(1sec)
// -o, --out-pipe-name - name of a pipe where wspiper will push received via ws messages, def - /tmp/wsoutpipe
// -i, --in-pipe-name - name of a pipe where wspiper will listen and receive messages and relay these messages to ws, def - /tmp/wsinpipe
// -n, --no-check-cert - do not check CA certs
// 
// -p, --ping-period - period of sending WS pings, ms, default - 1000(1sec)
// -g, --pong-timeout - Pong recv timeout, ms, default 3000(3s)
// 
// -d, --delimiter - set message delimiter. Default - \n. Possible values - \n, \n\n.., \t, \r, \r\n, <symbol>, \0 - null.

// TODO:
// -g, --origin - web-socket origin
// -v, --verbose - verbose logging
// -m, --max-msg-size - maximum message size in bytes, default - 65536 (64KB)
// -s, --pipes-buffer-size - size of named pipes buffer in bytes, default - 4096 (4KB)

#include <getopt.h>
#include "wsp_settings.h"

int get_cli_args(int argc, char* argv[], wsp_settings* settings);


#endif // WSP_CLI

