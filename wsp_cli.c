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
#include <stdlib.h>
#include <string.h>

#include "wsp_log.h"
#include "wsp_cli.h"
#include "wsp_settings.h"

int get_cli_args(int argc, char* argv[], wsp_settings* settings) {

    static struct option long_options[] = {
        {"connect", required_argument, 0, 'c'},
        {"timeout", required_argument, 0, 't'},
        {"no-check-cert", no_argument, 0, 'n'},
        {"reconnect", required_argument, 0, 'r'},
        {"out-pipe-name", required_argument, 0, 'o'},
        {"in-pipe-name", required_argument, 0, 'i'},
        {"ping-period", required_argument, 0, 'p'},
        {"pong-timeout", required_argument, 0, 'g'},
        {"delimiter", required_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    char* endptr;

    char* _srv_name = NULL;

    while ((opt = getopt_long(argc, argv, "c:t:r:o:i:n", long_options, &option_index)) != -1) {

        char opt_str[64];
        sprintf(opt_str, "Option %c", opt);

        switch (opt) {
        case 'c':
            size_t srvlen = strlen(optarg) + 1;
            _srv_name = malloc(srvlen);

            if (_srv_name) {
                memcpy(_srv_name, optarg, srvlen);
            }
            else {
                wsp_log(LOG_ERR, "Not enough memory");
                return -1;
            }

            break;

        case 't':

            settings->timeout = (int32_t)strtoul(optarg, &endptr, 10);
            if (*endptr != '\0') {
                wsp_log(LOG_ERR, "Incorrect value for --timeout/-t!");
                return -1;
            }
            break;

        case 'r':

            settings->reconnect = (int32_t)strtoul(optarg, &endptr, 10);
            if (*endptr != '\0') {
                wsp_log(LOG_ERR, "Incorrect value for --reconnect/-r!");
                return -1;
            }
            break;

        case 'p':

            settings->ping_period = (int32_t)strtoul(optarg, &endptr, 10);
            if (*endptr != '\0') {
                wsp_log(LOG_ERR, "Incorrect value for --ping-period/-p!");
                return -1;
            }
            break;

        case 'g':

            settings->pong_timeout = (int32_t)strtoul(optarg, &endptr, 10);
            if (*endptr != '\0') {
                wsp_log(LOG_ERR, "Incorrect value for --ping-period/-p!");
                return -1;
            }
            break;



        case 'n':
            settings->check_server_cert = false;
            break;

        case 'o':
            settings->output_pipe_name = malloc(strlen(optarg) + 1);
            if (settings->output_pipe_name) {
                strcpy(settings->output_pipe_name, optarg);
            }
            else {
                wsp_log(LOG_ERR, "Not enough memory for out pipe name");
                return -1;
            }
			settings->boutpipedef = false;
            break;

        case 'i':
            settings->input_pipe_name = malloc(strlen(optarg) + 1);
            if (settings->input_pipe_name) {
                strcpy(settings->input_pipe_name, optarg);
            }
            else {
                wsp_log(LOG_ERR, "Not enough memory for in pipe name");
                return -1;
            }
			settings->binpipedef = false;
            break;

		case 'd':
			settings->input_pipe_message_delimiter = malloc(strlen(optarg) + 1);
			if (settings->input_pipe_message_delimiter) {
				strcpy(settings->input_pipe_message_delimiter, optarg);
			}
			else {
				wsp_log(LOG_ERR, "Not enough memory for message delimiter");
				return -1;
			}
			settings->bdelimdef = false;
			break;

        default:
            return -1;
        }

    }


    //check required
    if (_srv_name == NULL) {
        wsp_log(LOG_INFO, "--connect <URI list> required\n");
        return -1;
    }
    settings->connection_string = _srv_name;

    if (!settings->output_pipe_name) {
        settings->output_pipe_name = malloc(strlen(DEF_OUT_PIPE_NAME) + 1);
        if (settings->output_pipe_name) {
            strcpy(settings->output_pipe_name, DEF_OUT_PIPE_NAME);
        }
        else {
            wsp_log(LOG_ERR, "Not enough memory for out pipe name");
            return -1;
        }
    }

    if (!settings->input_pipe_name) {
        settings->input_pipe_name = malloc(strlen(DEF_IN_PIPE_NAME) + 1);
        if (settings->input_pipe_name) {
            strcpy(settings->input_pipe_name, DEF_IN_PIPE_NAME);
        }
        else {
            wsp_log(LOG_ERR, "Not enough memory for in pipe name");
            return -1;
        }
    }

    return 0;
}
