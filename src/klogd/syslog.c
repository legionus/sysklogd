/*
 * Copyright (c) 1983, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted provided
 * that: (1) source distributions retain this entire copyright notice and
 * comment, and (2) distributions including binaries display the following
 * acknowledgement:  ``This product includes software developed by the
 * University of California, Berkeley and its contributors'' in the
 * documentation or other materials provided with the distribution and in
 * all advertising materials mentioning features or use of this software.
 * Neither the name of the University nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/syslog.h>
#undef syslog
#undef vsyslog
#include <sys/uio.h>
#include <sys/wait.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <paths.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>

#include "klogd.h"

#define _PATH_LOGNAME "/dev/log"

static int LogFile = -1;              /* fd for log */
static int connected;                 /* have done connect */
static int LogStat        = 0;        /* status bits, set by openlog() */
static const char *LogTag = "syslog"; /* string to tag the entry with */
static int LogFacility    = LOG_USER; /* default facility code */

void __vsyslog_chk(int pri, int flag, const char *fmt, va_list ap)
	SYSKLOGD_FORMAT((__printf__, 3, 0))
	SYSKLOGD_NONNULL((3));

void __syslog_chk(int pri, int flag, const char *fmt, ...)
	SYSKLOGD_FORMAT((__printf__, 3, 4))
	SYSKLOGD_NONNULL((3));

void __vsyslog_chk(int pri, SYSKLOGD_UNUSED(int flag), const char *fmt, va_list ap)
{
	register int cnt;
	register char *p;
	time_t now;
	int fd, saved_errno;
	int result;
	char tbuf[2048], fmt_cpy[1024], *stdp = (char *) 0;

	saved_errno = errno;

	/* see if we should just throw out this message */
	if (!LOG_MASK(LOG_PRI(pri)) || (pri & ~(LOG_PRIMASK | LOG_FACMASK)))
		return;
	if (LogFile < 0 || !connected)
		openlog(LogTag, LogStat | LOG_NDELAY, LogFacility);

	/* set default facility if none specified */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	/* build the message */
	(void) time(&now);
	(void) sprintf(tbuf, "<%d>%.15s ", pri, ctime(&now) + 4);
	for (p = tbuf; *p; ++p)
		;
	if (LogStat & LOG_PERROR)
		stdp = p;
	if (LogTag) {
		(void) strcpy(p, LogTag);
		for (; *p; ++p)
			;
	}
	if (LogStat & LOG_PID) {
		(void) sprintf(p, "[%d]", getpid());
		for (; *p; ++p)
			;
	}
	if (LogTag) {
		*p++ = ':';
		*p++ = ' ';
	}

	/* substitute error message for %m */
	{
		register char ch, *t1, *t2;
		// char *strerror();

		for (t1 = fmt_cpy;
		     (ch = *fmt) != '\0' && t1 < fmt_cpy + sizeof(fmt_cpy);
		     ++fmt)
			if (ch == '%' && fmt[1] == 'm') {
				++fmt;
				for (t2 = strerror(saved_errno);
				     (*t1 = *t2++); ++t1)
					;
			} else
				*t1++ = ch;
		*t1 = '\0';
	}

	(void) vsprintf(p, fmt_cpy, ap);

	cnt = strlen(tbuf);

	/* output to stderr if requested */
	if (LogStat & LOG_PERROR) {
		struct iovec iov[2];
		register struct iovec *v = iov;

		v->iov_base = stdp;
		v->iov_len  = cnt - (stdp - tbuf);
		++v;
		v->iov_base = (void *) "\n";
		v->iov_len  = 1;

		if (writev(2, iov, 2) < 0)
			errno = 0; // ignore
	}

	/* output the message to the local logger */
	result = write(LogFile, tbuf, cnt + 1);

	if (result == -1 && (errno == ECONNRESET || errno == ENOTCONN || errno == ECONNREFUSED)) {
		closelog();
		openlog(LogTag, LogStat | LOG_NDELAY, LogFacility);
		result = write(LogFile, tbuf, cnt + 1);
	}

	if (result >= 0 || !(LogStat & LOG_CONS))
		return;

	/*
	 * output the message to the console; don't worry about
	 * blocking, if console blocks everything will.
	 */
	if ((fd = open(_PATH_CONSOLE, O_WRONLY | O_NOCTTY, 0)) < 0)
		return;
	(void) strcat(tbuf, "\r\n");
	cnt += 2;
	p = index(tbuf, '>') + 1;

	if (write(fd, p, cnt - (p - tbuf)) < 0)
		errno = 0; // ignore

	(void) close(fd);
}

void __syslog_chk(int pri, int flag, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__vsyslog_chk(pri, flag, fmt, ap);
	va_end(ap);
}

void vsyslog(int pri, const char *fmt, va_list ap)
{
	__vsyslog_chk(pri, -1, fmt, ap);
}

void syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

static struct sockaddr SyslogAddr; /* AF_UNIX address of local logger */
/*
 * OPENLOG -- open system log
 */
void openlog(const char *ident, int logstat, int logfac)
{
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;

#ifdef ALLOW_KERNEL_LOGGING
	if ((logfac & ~LOG_FACMASK) == 0)
#else
	if (logfac != 0 && (logfac & ~LOG_FACMASK) == 0)
#endif
		LogFacility = logfac;

	if (LogFile == -1) {
		SyslogAddr.sa_family = AF_UNIX;
		strncpy(SyslogAddr.sa_data, _PATH_LOGNAME,
		        sizeof(SyslogAddr.sa_data));
		if (LogStat & LOG_NDELAY) {
			LogFile = socket(AF_UNIX, SOCK_DGRAM, 0);
			/*			fcntl(LogFile, F_SETFD, 1); */
		}
	}
	if (LogFile != -1 && !connected &&
	    connect(LogFile, &SyslogAddr, sizeof(SyslogAddr.sa_family) + strlen(SyslogAddr.sa_data)) != -1)
		connected = 1;
}

/*
 * CLOSELOG -- close the system log
 */
void closelog(void)
{
	(void) close(LogFile);
	LogFile   = -1;
	connected = 0;
}

static int LogMask = 0xff; /* mask of priorities to be logged */
/*
 * SETLOGMASK -- set the log mask level
 */
int setlogmask(int pmask)
{
	int omask;

	omask = LogMask;
	if (pmask != 0)
		LogMask = pmask;
	return (omask);
}
