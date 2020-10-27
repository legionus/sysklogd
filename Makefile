#   Copyright (c) 1995  Dr. G.W. Wettstein <greg@wind.rmcc.com>
#   Copyright (c) 2007  Martin Schulze <joey@infodrom.org>
#
#   This file is part of the sysklogd package, a kernel and system log daemon.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

CC= gcc
#SKFLAGS= -g -Wall
#LDFLAGS= -g
SKFLAGS= $(RPM_OPT_FLAGS) -D_GNU_SOURCE -O3 -fomit-frame-pointer -Wall -fno-strength-reduce
# -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
# -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
# $(shell getconf LFS_SKFLAGS)
LDFLAGS= -s

# Look where your install program is.
INSTALL = /usr/bin/install

# Destination paths, set prefix=/opt if required
BINDIR = $(prefix)/usr/sbin
MANDIR = $(prefix)/usr/share/man

# There is one report that under an all ELF system there may be a need to
# explicilty link with libresolv.a.  If linking syslogd fails you may wish
# to try uncommenting the following define.
# LIBS = /usr/lib/libresolv.a

# A patch was forwarded which provided support for sysklogd under
# the ALPHA.  This patch included a reference to a library which may be
# specific to the ALPHA.  If you are attempting to build this package under
# an ALPHA and linking fails with unresolved references please try
# uncommenting the following define.
# LIBS = ${LIBS} -linux

# Define the following to impart start-up delay in klogd.  This is
# useful if klogd is started simultaneously or in close-proximity to syslogd.
# KLOGD_START_DELAY = -DKLOGD_DELAY=5

# The following define determines whether the package adheres to the
# file system standard.
FSSTND = -DFSSTND

# The following define determines whether the syslogd should create checksum
# chains for log entries.
USE_CHECKSUMS = -DUSE_CHECKSUMS

# The following define establishes ownership for the man pages.
# Avery tells me that there is a difference between Debian and
# Slackware.  Rather than choose sides I am leaving it up to the user.
MAN_USER = root
MAN_GROUP = root
MAN_PERMS = 644

# The following define establishes the name of the pid file for the
# syslogd daemon.  The library include file (paths.h) defines the
# name for the syslogd pid to be syslog.pid.  A number of people have
# suggested that this should be syslogd.pid.  You may cast your
# ballot below.
SYSLOGD_PIDNAME = -DSYSLOGD_PIDNAME=\"syslogd.pid\"

SYSLOGD_FLAGS= -DSYSLOG_INET -DSYSLOG_UNIXAF -DINET6 -DNO_SCCS \
	${USE_CHECKSUMS} ${FSSTND} ${SYSLOGD_PIDNAME}
SYSLOG_FLAGS= -DALLOW_KERNEL_LOGGING
KLOGD_FLAGS = ${FSSTND} ${KLOGD_START_DELAY}
DEB =

TESTS = \
	facility-splitting \
	priority-splitting \
	priority-exclusion \
	priority-exclamation \
	named-pipes

ifneq (${USE_CHECKSUMS},)
TESTS += log-hashes
endif

all: syslogd klogd

test:
	@export TOPDIR="$(CURDIR)"; \
	suiterc=0; \
	for n in $(TESTS); do \
	  tests/travis-command-start "$$n" "test.$$n"; \
	  echo "### Check: $$n ... "; \
	  if ! "tests/run" "$$n"; then \
	    echo "Test FAILED"; \
	    suiterc=1; \
	  fi; \
	  tests/travis-command-stop "$$n"; \
	done; \
	exit $$suiterc;

install: install_man install_exec

syslogd: syslogd.o pidfile.o block/sha256.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

klogd:	klogd.o syslog.o pidfile.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

syslogd.o: syslogd.c version.h
	${CC} ${SKFLAGS} ${SYSLOGD_FLAGS} $(DEB) -c $<

syslog.o: syslog.c
	${CC} ${SKFLAGS} ${SYSLOG_FLAGS} -c $<

klogd.o: klogd.c klogd.h version.h
	${CC} ${SKFLAGS} ${KLOGD_FLAGS} $(DEB) -c $<

clean:
	rm -f *.o *.log *~ *.orig
	rm -f *.ko oops.mod.* Module.symvers

clobber: clean
	rm -f syslogd klogd TAGS

install_exec: syslogd klogd
	${INSTALL} -m 500 -s syslogd ${BINDIR}/syslogd
	${INSTALL} -m 500 -s klogd ${BINDIR}/klogd

install_man:
	${INSTALL} -o ${MAN_USER} -g ${MAN_GROUP} -m ${MAN_PERMS} sysklogd.8 ${MANDIR}/man8/sysklogd.8
	${INSTALL} -o ${MAN_USER} -g ${MAN_GROUP} -m ${MAN_PERMS} syslogd.8 ${MANDIR}/man8/syslogd.8
	${INSTALL} -o ${MAN_USER} -g ${MAN_GROUP} -m ${MAN_PERMS} syslog.conf.5 ${MANDIR}/man5/syslog.conf.5
	${INSTALL} -o ${MAN_USER} -g ${MAN_GROUP} -m ${MAN_PERMS} klogd.8 ${MANDIR}/man8/klogd.8

obj-m += oops.o

oops.ko: oops.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
