#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sysklog], [1.6.0], [gladkov.alexey@gmail.com])
AC_CONFIG_SRCDIR([src/attribute.h])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([subdir-objects color-tests dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h paths.h stddef.h \
		  stdint.h stdlib.h string.h sys/file.h sys/ioctl.h \
		  sys/param.h sys/socket.h sys/time.h syslog.h unistd.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_STRNLEN
AC_FUNC_WAIT3

AC_CHECK_FUNC([alarm],         [], [AC_MSG_ERROR([required function 'alarm' is missing.])])
AC_CHECK_FUNC([epoll_create1], [], [AC_MSG_ERROR([required function 'epoll_create1' is missing.])])
AC_CHECK_FUNC([epoll_ctl],     [], [AC_MSG_ERROR([required function 'epoll_ctl' is missing.])])
AC_CHECK_FUNC([epoll_wait],    [], [AC_MSG_ERROR([required function 'epoll_wait' is missing.])])
AC_CHECK_FUNC([dup2],          [], [AC_MSG_ERROR([required function 'dup2' is missing.])])

CC_CHECK_CFLAGS_APPEND([\
	-fomit-frame-pointer \
	-fno-strength-reduce \
	-Wall \
	-Wstrict-prototypes \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wmissing-format-attribute \
	-Wdisabled-optimization \
	-Wwrite-strings \
	-Wcast-align \
	-Wshadow \
])

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING([--enable-werror], [turn on -Werror for some kind of warnings])],
	[use_werror=$enableval], [use_werror=no])

if test "$use_werror" = yes; then
	CC_CHECK_CFLAGS_APPEND([-Werror])
fi

AC_ARG_WITH(klog-start-delay,
	AS_HELP_STRING(--with-klog-start-delay=NSECS, [Start-up delay in klogd]),
	[AC_DEFINE([KLOGD_DELAY], $withval, [KLOGD_DELAY])])

AC_ARG_ENABLE(checksums,
	AS_HELP_STRING(--disable-checksums, [Whether the syslogd should create checksum chains for log entries]),
	[use_checksums=$enableval], [use_checksums=yes])

if test "$use_checksums" != no; then
	AC_DEFINE([USE_CHECKSUMS], 1, [Whether the syslogd should create checksum chains for log entries])
fi

AC_ARG_ENABLE(inet-family,
	AS_HELP_STRING(--disable-inet-family, [Whether the syslogd should use INET protocol family]),
	[use_inet_family=$enableval], [use_inet_family=yes])

if test "$use_inet_family" != no; then
	AC_DEFINE([SYSLOG_INET], 1, [Use INET protocol to receive messages])
fi

AC_ARG_ENABLE(inet6_family,
	AS_HELP_STRING(--disable-inet6-family, [Whether the syslogd should use INET6 protocol family]),
	[use_inet6_family=$enableval], [use_inet6_family=yes])

if test "$use_inet6_family" != no; then
	AC_DEFINE([SYSLOG_INET6], 1, [Use INET6 protocol to receive messages])
fi

AC_ARG_ENABLE(unix-domain,
	AS_HELP_STRING(--disable-unix-domain, [Whether the syslogd should use UNIX domain sockets]),
	[use_unix_domain=$enableval], [use_unix_domain=yes])

if test "$use_unix_domain" != no; then
	AC_DEFINE([SYSLOG_UNIXAF], 1, [Use UNIX domain sockets to receive messages])
fi

AC_CONFIG_FILES([Makefile
                 man/Makefile
                 src/Makefile
                 src/klogd/Makefile
                 src/syslogd/Makefile
		 tests/Makefile])
AC_OUTPUT

AC_MSG_RESULT([
	$PACKAGE $VERSION
	=============

	prefix:   ${prefix}
	libdir:   ${libdir}
	bindir:   ${bindir}
	datadir:  ${datadir}

	compiler: ${CC}
	cflags:   ${CFLAGS}

	Create checksum chains:    ${use_checksums}
	Use INET protocol family:  ${use_inet_family}
	Use INET6 protocol family: ${use_inet6_family}
	Use UNIX domain sockets:   ${use_unix_domain}
])
