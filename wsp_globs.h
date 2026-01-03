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
#ifndef WSP_GLOBS
#define WSP_GLOBS

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

#include "wsp_settings.h"

extern uint32_t g_threads_run;

extern pthread_t g_thrdid_socket;
extern pthread_t g_thrdid_piperead;
extern pthread_t g_thrdid_pipewrite;

extern wsp_settings g_settings;

extern int g_ctl_pipe_for_piperead[2];
extern int g_ctl_pipe_for_pipewrite[2];
extern int g_ctl_pipe_for_pipesock[2];

extern int g_pipe_sock_to_write[2];
extern int g_pipe_read_to_sock[2];

void send_threads_stop();

#endif // !WSP_GLOBS

