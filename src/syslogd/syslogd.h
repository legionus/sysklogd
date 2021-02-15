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
#ifndef _SYSLOGD_H_
#define _SYSLOGD_H_

#include "attribute.h"

enum input_type {
	INPUT_NONE = 0,
	INPUT_UNIX,
	INPUT_INET,
	INPUT_SIGNALFD,
};

/* values for globals.options */
enum option_flag {
	OPT_SEND_TO_ALL   = (1 << 0), /* send message to all IPv4/IPv6 addresses */
	OPT_FORK          = (1 << 1), /* don't fork - don't run in daemon mode */
	OPT_COMPRESS      = (1 << 2), /* compress repeated messages flag */
	OPT_NET_HOPS      = (1 << 3), /* can we bounce syslog messages through an
	                               * intermediate host. */
	OPT_ACCEPT_REMOTE = (1 << 4), /* receive messages that come via UDP */
};

struct globals {
	int family;
	int verbose;
	unsigned options;
	char *chroot_dir;           /* new server root directory */
	char *server_user;          /* user name to run server as */
	char *bind_addr;            /* bind UDP port to this interface only */
	unsigned int mark_interval; /* interval between marks in seconds */
	char **strip_domains;       /* these domains may be stripped before writing logs */
	char **local_hosts;         /* these hosts are logged with their hostname */
	const char *devlog;
	const char *config_file;
	const char *funix_dir;
};

extern int set_input(enum input_type type, const char *name, int fd);
extern void parse_arguments(int argc, char **argv, struct globals *g);

#endif /* _SYSLOGD_H_ */
