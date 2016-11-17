/* sysdep_syslog.c - Logging via syslog
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#include "nhrp_defines.h"
#include "nhrp_common.h"

int log_init(void)
{
	openlog("opennhrp", LOG_PERROR | LOG_PID, LOG_DAEMON);

	return TRUE;
}

void nhrp_log(int level, const char *format, ...)
{
	va_list va;
	int l;

	switch (level) {
	case NHRP_LOG_ERROR:
		l = LOG_ERR;
		break;
	case NHRP_LOG_INFO:
		l = LOG_INFO;
		break;
	case NHRP_LOG_DEBUG:
	default:
		l = LOG_DEBUG;
		break;
	}

	va_start(va, format);
	vsyslog(l, format, va);
	va_end(va);
}

void nhrp_perror(const char *message)
{
	nhrp_error("%s: %s", message, strerror(errno));
}
