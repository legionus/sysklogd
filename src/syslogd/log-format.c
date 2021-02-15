// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2021  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is part of the sysklogd package, a kernel and system log daemon.
 *
 * GNU Inetutils is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or (at
 * your option) any later version.
 *
 * GNU Inetutils is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see `http://www.gnu.org/licenses/'.
 */

#include "config.h"

#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "syslogd.h"

static ssize_t iovec_max = 0;
static int set_log_format_field(struct log_format *log_fmt, enum log_format_type t, const char *s, size_t n) SYSKLOGD_NONNULL((1));

int set_log_format_field(struct log_format *fmt, enum log_format_type t, const char *s, size_t n)
{
	struct iovec *iov;
	enum log_format_type *type;

	if (fmt->iov_nr >= (size_t) iovec_max) {
		logerror("Too many parts in the log_format string");
		return -1;
	}

	iov = realloc(fmt->iov, sizeof(*iov) * (fmt->iov_nr + 1));
	if (!iov) {
		logerror("Cannot allocate record for log_format string");
		return -1;
	}
	fmt->iov = iov;

	fmt->iov[fmt->iov_nr].iov_base = (char *) s;
	fmt->iov[fmt->iov_nr].iov_len  = n;

	type = realloc(fmt->type, sizeof(*type) * (fmt->iov_nr + 1));
	if (!type) {
		logerror("Cannot allocate field for log_format string");
		return -1;
	}

	fmt->type = type;
	fmt->type[fmt->iov_nr] = t;
	fmt->mask |= (1U << t);

	fmt->iov_nr++;

	return 0;
}

int parse_log_format(struct log_format *fmt, const char *str)
{
	const char *ptr, *start;
	int i, special;
	struct log_format new_fmt = { 0 };

	iovec_max = sysconf(_SC_IOV_MAX);
	if (iovec_max < 0) {
		logerror("unable to get maximum number of `iovec' structures that one process");
		iovec_max = 1024;
	}

	new_fmt.line = strdup(str);
	if (!new_fmt.line) {
		logerror("Cannot allocate log_format string");
		goto error;
	}

	ptr = str;
	i = special = 0;

	while (*ptr != '\0') {
		char c = *ptr++;

		switch (c) {
			case 'b':
				if (special) c = '\b';
				break;
			case 'f':
				if (special) c = '\f';
				break;
			case 'n':
				if (special) c = '\n';
				break;
			case 'r':
				if (special) c = '\r';
				break;
			case 't':
				if (special) c = '\t';
				break;
			case '\\':
				if (!special) {
					special = 1;
					continue;
				}
				break;
		}
		new_fmt.line[i++] = c;
		special           = 0;
	}

	special = 0;

	if (set_log_format_field(&new_fmt, LOG_FORMAT_BOL, NULL, 0) < 0)
		goto error;

	start = ptr = new_fmt.line;

	while (*ptr != '\0') {
		enum log_format_type f_type;

		if (special) {
			switch (*ptr) {
				case 't':
					f_type = LOG_FORMAT_TIME;
					break;
				case 'h':
					f_type = LOG_FORMAT_HOST;
					break;
				case 'm':
					f_type = LOG_FORMAT_MSG;
					break;
				case 'u':
					f_type = LOG_FORMAT_UID;
					break;
				case 'g':
					f_type = LOG_FORMAT_GID;
					break;
				case 'p':
					f_type = LOG_FORMAT_PID;
					break;
				case 'P':
					f_type = LOG_FORMAT_PRI;
					break;
				case 'H':
					f_type = LOG_FORMAT_HASH;
					break;
				case 'T':
					f_type = LOG_FORMAT_TAG;
					break;
				case 'C':
					f_type = LOG_FORMAT_CONTENT;
					break;
				case '%':
					special = 0;
					goto create_special;
				default:
					logerror("unexpected special: '%%%c'", *ptr);
					goto error;
			}
			special = 0;
			goto create_field;

		} else if (*ptr == '%')
			special = 1;
	next:
		ptr++;
		continue;
	create_field:
		if ((ptr - start - 1) > 0 &&
		    set_log_format_field(&new_fmt, LOG_FORMAT_NONE, start, (size_t)(ptr - start - 1)) < 0)
			goto error;

		if (set_log_format_field(&new_fmt, f_type, NULL, 0) < 0)
			goto error;

		start = ptr + 1;
		goto next;
	create_special:
		if (set_log_format_field(&new_fmt, LOG_FORMAT_NONE, start, (size_t)(ptr - start - 1)) < 0)
			goto error;

		start = ptr;
		goto next;
	}

	if (special) {
		logerror("unexpected '%%' at the end of line");
		goto error;
	}

	if (start != ptr &&
	    set_log_format_field(&new_fmt, LOG_FORMAT_NONE, start, (size_t)(ptr - start)) < 0)
		goto error;

	if (set_log_format_field(&new_fmt, LOG_FORMAT_EOL, NULL, 0) < 0)
		goto error;

	free(fmt->line);
	free(fmt->iov);
	free(fmt->type);

	fmt->line   = new_fmt.line;
	fmt->iov    = new_fmt.iov;
	fmt->iov_nr = new_fmt.iov_nr;
	fmt->type   = new_fmt.type;

	return 0;
error:
	free_log_format(&new_fmt);

	return -1;
}

void free_log_format(struct log_format *fmt)
{
	free(fmt->line);
	free(fmt->iov);
	free(fmt->type);
}
