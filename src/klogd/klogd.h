/*
    klogd.h - main header file for Linux kernel log daemon.
    Copyright (c) 1995  Dr. G.W. Wettstein <greg@wind.rmcc.com>

    This file is part of the sysklogd package, a kernel and system log daemon.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* Useful include files. */
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include "attribute.h"

#undef syslog
#undef vsyslog

/* Function prototypes. */
void Syslog(int priority, const char *fmt, ...)
	SYSKLOGD_FORMAT((__printf__, 2, 3))
	SYSKLOGD_NONNULL((2));

void vsyslog(int pri, const char *fmt, va_list ap)
	SYSKLOGD_FORMAT((__printf__, 2, 0))
	SYSKLOGD_NONNULL((2));

void syslog(int pri, const char *fmt, ...)
	SYSKLOGD_FORMAT((__printf__, 2, 3))
	SYSKLOGD_NONNULL((2));

