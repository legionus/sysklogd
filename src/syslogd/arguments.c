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
/*
 * Copyright (c) 1983, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <getopt.h>
#include <pwd.h>
#include <err.h>

#include "syslogd.h"

#define LIST_DELIMITER ':' /* delimiter between two hosts */

char **crunch_list(char *list);
void usage(void) SYSKLOGD_NORETURN();

void usage(void)
{
	fprintf(stderr, "usage: syslogd [-46Acdrvh] [-l hostlist] [-m markinterval] [-n] [-p path]\n"
	                " [-s domainlist] [-f conffile] [-i IP address] [-u username]\n");
	exit(1);
}

char **crunch_list(char *list)
{
	int i, m, n;
	char *p, *q;
	char **result = NULL;

	p = list;

	/* strip off trailing delimiters */
	while (*p && p[strlen(p) - 1] == LIST_DELIMITER)
		p[strlen(p) - 1] = '\0';
	/* cut off leading delimiters */
	while (p[0] == LIST_DELIMITER)
		p++;

	/* count delimiters to calculate the number of elements */
	for (n = i = 0; p[i]; i++)
		if (p[i] == LIST_DELIMITER) n++;

	if (!(result = malloc(sizeof(char *) * (n + 2))))
		errx(1, "can't get enough memory.");

	/*
	 * We now can assume that the first and last
	 * characters are different from any delimiters,
	 * so we don't have to care about this.
	 */
	m = 0;
	while ((q = strchr(p, LIST_DELIMITER)) && m < n) {
		result[m] = malloc((q - p + 1) * sizeof(char));
		if (!result[m])
			errx(1, "can't get enough memory.");

		memcpy(result[m], p, q - p);
		result[m][q - p] = '\0';

		p = q;
		p++;
		m++;
	}
	if (!(result[m] = strdup(p)))
		errx(1, "can't get enough memory.");

	result[++m] = NULL;

	return result;
}

void parse_arguments(int argc, char **argv, struct globals *g)
{
	int c;

	g->devlog        = _PATH_LOG;
	g->config_file   = "/etc/syslog.conf";
	g->funix_dir     = "/etc/syslog.d";
	g->mark_interval = 20 * 60;
	g->options       = OPT_COMPRESS | OPT_FORK;

#ifdef SYSLOG_INET6
	g->family = PF_UNSPEC; /* protocol family (IPv4, IPv6 or both) */
#else
	g->family = PF_INET; /* protocol family (IPv4 only) */
#endif

	while ((c = getopt(argc, argv, "46Aa:bcdhf:i:j:l:m:np:P:rs:u:v")) != EOF) {
		switch (c) {
			case '4':
				g->family = PF_INET;
				break;
#ifdef SYSLOG_INET6
			case '6':
				g->family = PF_INET6;
				break;
#endif
			case 'A':
				g->options |= OPT_SEND_TO_ALL;
				break;
			case 'a':
				set_input(INPUT_UNIX, optarg, -1);
				break;
			case 'b':
				g->options |= OPT_BOOT_ID;
				break;
			case 'c': /* don't compress repeated messages */
				g->options &= ~OPT_COMPRESS;
				break;
			case 'd': /* verbosity */
				g->verbose++;
				break;
			case 'f': /* configuration file */
				g->config_file = optarg;
				break;
			case 'h':
				g->options |= OPT_NET_HOPS;
				break;
			case 'i':
				if (g->bind_addr) {
					warnx("only one -i argument allowed, "
					      "the first one is taken.");
					break;
				}
				g->bind_addr = optarg;
				break;
			case 'j':
				g->chroot_dir = optarg;
				break;
			case 'l':
				if (g->local_hosts) {
					warnx("only one -l argument allowed, "
					      "the first one is taken.");
					break;
				}
				g->local_hosts = crunch_list(optarg);
				break;
			case 'm': /* mark interval */
				g->mark_interval = atoi(optarg) * 60;
				break;
			case 'n': /* don't fork */
				g->options &= ~OPT_FORK;
				break;
			case 'p': /* path to regular log socket */
				g->devlog = optarg;
				break;
			case 'P':
				g->funix_dir = optarg;
				break;
			case 'r': /* accept remote messages */
				g->options |= OPT_ACCEPT_REMOTE;
				break;
			case 's':
				if (g->strip_domains) {
					warnx("only one -s argument allowed,"
					      "the first one is taken.");
					break;
				}
				g->strip_domains = crunch_list(optarg);
				break;
			case 'u':
				g->server_user = optarg;
				break;
			case 'v':
				printf("syslogd %s\n", VERSION);
				exit(0);
			case '?':
			default:
				usage();
		}
	}

	if ((argc -= optind))
		usage();
}
