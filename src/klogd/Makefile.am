sbin_PROGRAMS = klogd

klogd_CFLAGS  = -I$(srcdir)/.. -D_GNU_SOURCE
klogd_SOURCES = $(srcdir)/klogd.c \
		$(srcdir)/klogd.h \
		$(srcdir)/syslog.c \
		$(srcdir)/../pidfile.c \
		$(srcdir)/../pidfile.h \
		$(srcdir)/../attribute.h
