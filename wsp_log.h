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
#ifndef _LOG_H
#define _SETUP_H

#include <syslog.h>

#define LOG_IDENT	"wspiper"

int wsp_loginit();
int wsp_logclose();

/*
int wsp_log(int prio, const char* logmsg);
*/
int wsp_log(int prio, const char* fmt, ...);


#endif