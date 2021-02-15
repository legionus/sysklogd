sbin_PROGRAMS = syslogd
syslogd_CFLAGS  = -I$(srcdir)/.. -D_GNU_SOURCE
syslogd_SOURCES = $(srcdir)/syslogd.c \
		  $(srcdir)/syslogd.h \
		  $(srcdir)/arguments.c \
		  $(srcdir)/sha256.c \
		  $(srcdir)/sha256.h \
		  $(srcdir)/bswap.h \
		  $(srcdir)/hash.h \
		  $(srcdir)/../pidfile.c \
		  $(srcdir)/../pidfile.h \
		  $(srcdir)/../attribute.h
