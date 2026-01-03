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
#include <stdarg.h>
#include <stdlib.h>
#include "wsp_log.h"

int wsp_loginit() {
	openlog(LOG_IDENT, LOG_PID | LOG_CONS, LOG_USER);

	return EXIT_SUCCESS;
}

int wsp_logclose() {
	closelog();

	return EXIT_SUCCESS;
}

int wsp_log(int prio, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

	// calc needed size
    va_list args_copy;
    va_copy(args_copy, args);
    int vs_ret = vsnprintf(NULL, 0, fmt, args_copy);
	if (vs_ret < 0) return -1; // error
    size_t needed = (size_t)vs_ret;
    va_end(args_copy);

    if (needed < 0) {
        va_end(args);
        return -1;
    }

    char* buf = malloc(needed + 1);
    if (!buf) {
        va_end(args);
        return -1;
    }

    vsnprintf(buf, needed + 1, fmt, args);
    va_end(args);

    syslog(prio, "%s", buf);
    printf("%s\n", buf);

    free(buf);
    return 0;
}
