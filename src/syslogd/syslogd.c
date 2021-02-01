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

#define MAXLINE    1024 /* maximum line length */
#define MAXSVLINE  240  /* maximum saved line length */
#define DEFUPRI    (LOG_USER | LOG_NOTICE)
#define TIMERINTVL 30 /* interval for checking flush, mark */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <utmp.h>
#include <ctype.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#include <time.h>
#include <err.h>

#define SYSLOG_NAMES
#include <sys/syslog.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <signal.h>

#include <netinet/in.h>
#include <netdb.h>
#include <syscall.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <dirent.h>
#include <pwd.h>
#include <grp.h>

#include "pidfile.h"
#include "attribute.h"
#include "hash.h"

#include <paths.h>

#ifndef UTMP_FILE
#ifdef UTMP_FILENAME
#define UTMP_FILE UTMP_FILENAME
#else
#ifdef _PATH_UTMP
#define UTMP_FILE _PATH_UTMP
#else
#define UTMP_FILE "/etc/utmp"
#endif
#endif
#endif

#ifndef _PATH_LOGCONF
#define _PATH_LOGCONF "/etc/syslog.conf"
#endif

#ifndef _PATH_LOGPID
#define _PATH_LOGPID _PATH_VARRUN "syslogd.pid"
#endif

#ifndef _PATH_DEV
#define _PATH_DEV "/dev/"
#endif

#ifndef _PATH_CONSOLE
#define _PATH_CONSOLE "/dev/console"
#endif

#ifndef _PATH_TTY
#define _PATH_TTY "/dev/tty"
#endif

#ifndef _PATH_LOG
#define _PATH_LOG "/dev/log"
#endif

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "/dev/null"
#endif

static const char *ConfFile = _PATH_LOGCONF;
static const char *PidFile  = _PATH_LOGPID;

static char **parts;

static int verbose = 0;

enum input_type {
	INPUT_NONE = 0,
	INPUT_UNIX,
	INPUT_INET,
	INPUT_SIGNALFD,
};

struct input {
	enum input_type type;
	const char *name;
	int fd;
	struct input *next;
};

static struct input *inputs = NULL;
static int epoll_fd         = -1;
static int signal_fd        = -1;
static sigset_t signal_mask;

#ifdef UT_NAMESIZE
#define UNAMESZ UT_NAMESIZE /* length of a login name */
#else
#define UNAMESZ 8 /* length of a login name */
#endif
#define MAXUNAMES 20 /* maximum number of user names */
#define MAXFNAME  200 /* max file pathname length */

#define INTERNAL_NOPRI 0x10 /* the "no priority" priority */
#define TABLE_NOPRI    0 /* Value to indicate no priority in f_pmask */
#define TABLE_ALLPRI   0xFF /* Value to indicate all priorities in f_pmask */
#define LOG_MARK       LOG_MAKEPRI(LOG_NFACILITIES, 0) /* mark "facility" */

#define MAX_PRI 191 /* Maximum Priority per RFC 3164 */

/*
 * Flags to logmsg().
 */
#define IGN_CONS  0x001 /* don't print on console */
#define SYNC_FILE 0x002 /* do fsync on file after printing */
#define MARK      0x004 /* this message is a mark */

/*
 * Flags to set_pmask().
 */
#define PMASK_FLAG_IGNOREPRI 0x01
#define PMASK_FLAG_SINGLEPRI 0x02

/*
 * Option for create_unix_socket().
 */
enum unixaf_option {
	UNIXAF_BIND = 0,
	UNIXAF_CONNECT,
};

/* values for f_type */
enum f_type {
	F_UNUSED = 0, /* unused entry */
	F_FILE,       /* regular file */
	F_TTY,        /* terminal */
	F_CONSOLE,    /* console terminal */
	F_FORW,       /* remote machine */
	F_USERS,      /* list of users */
	F_WALL,       /* everyone logged on */
	F_FORW_SUSP,  /* suspended host forwarding */
	F_FORW_UNKN,  /* unknown host forwarding */
	F_PIPE,       /* named pipe */
	F_UNIXAF,     /* unix domain socket */
};

/*
 * This structure represents the files that will have log
 * copies printed.
 */

struct filed {
	enum f_type f_type;                  /* entry type, see below */
	int f_file;                          /* file descriptor */
	time_t f_time;                       /* time this was last written */
	char *f_host;                        /* host from which to recd. */
	u_char f_pmask[LOG_NFACILITIES + 1]; /* priority mask */
	union {
		char f_uname[MAXUNAMES][UNAMESZ + 1];
		struct {
			char f_hname[MAXHOSTNAMELEN + 1];
			struct addrinfo *f_addr;
		} f_forw; /* forwarding address */
		char f_fname[MAXFNAME];
	} f_un;
	char f_prevline[MAXSVLINE];          /* last message logged */
	time_t f_lasttime;                   /* time of last occurrence */
	char f_prevhost[MAXHOSTNAMELEN + 1]; /* host from which recd. */
	unsigned int f_prevpri;              /* pri of f_prevline */
	size_t f_prevlen;                    /* length of f_prevline */
	int f_prevcount;                     /* repetition cnt of prevline */
	int f_repeatcount;                   /* number of "repeated" msgs */
	int f_flags;                         /* store some additional flags */
	/* hash of last logged message */
	char f_prevhash[HASH_NAMESZ + 1 + HASH_HEXSZ + 1];
	struct filed *next;
};

/*
 * Intervals at which we flush out "message repeated" messages,
 * in seconds after previous message is logged.  After each flush,
 * we move to the next interval until we reach the largest.
 */
static time_t repeatinterval[] = { 30, 60 }; /* # of secs before flush */
#define MAXREPEAT     ((int) ((sizeof(repeatinterval) / sizeof(repeatinterval[0])) - 1))
#define REPEATTIME(f) ((f)->f_time + repeatinterval[(f)->f_repeatcount])
#define BACKOFF(f)                                      \
	{                                               \
		if (++(f)->f_repeatcount > MAXREPEAT)   \
			(f)->f_repeatcount = MAXREPEAT; \
	}
#ifdef SYSLOG_INET
#define INET_SUSPEND_TIME 180 /* equal to 3 minutes */
#define INET_RETRY_MAX    10 /* maximum of retries for getaddrinfo() */
#endif

#define LIST_DELIMITER ':' /* delimiter between two hosts */

static const char *TypeNames[] = {
	"UNUSED", "FILE", "TTY", "CONSOLE",
	"FORW", "USERS", "WALL", "FORW(SUSPENDED)",
	"FORW(UNKNOWN)", "PIPE", "UNIXAF"
};

static struct filed *files = NULL;
static struct filed consfile;

/*
 * From busybox-1.31.1:
 *
 * musl decided to be funny and it implements these as giant defines
 * of the form: ((CODE *)(const CODE []){ ... })
 * Which works, but causes _every_ function using them
 * to have a copy on stack (at least with gcc-6.3.0).
 * If we reference them just once, this saves 150 bytes.
 * The pointers themselves are optimized out
 * (no size change on uclibc).
 */
static const CODE *const bb_prioritynames = prioritynames;
static const CODE *const bb_facilitynames = facilitynames;

static const CODE InputTypeNames[] = {
	{ (char *) "NONE", INPUT_NONE },
	{ (char *) "INET", INPUT_INET },
	{ (char *) "UNIX", INPUT_UNIX },
	{ (char *) "SIGNALFD", INPUT_SIGNALFD },
	{ NULL, -1 }
};

#define SINFO_ISINTERNAL 0x01
#define SINFO_HAVECRED   0x02
#define SINFO_KLOG       0x04
#define SINFO_TIMESTAMP  0x08

struct sourceinfo {
	char *hostname;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	unsigned int flags;
};

enum log_format_type {
	LOG_FORMAT_NONE = 0,
	LOG_FORMAT_BOL,
	LOG_FORMAT_HASH,
	LOG_FORMAT_TIME,
	LOG_FORMAT_HOST,
	LOG_FORMAT_PID,
	LOG_FORMAT_UID,
	LOG_FORMAT_GID,
	LOG_FORMAT_MSG,
	LOG_FORMAT_EOL,
	LOG_FORMAT_COUNTS,
};

#define LOG_FORMAT_REPEAT_MAX 5
#define LOG_FORMAT_FIELDS_MAX LOG_FORMAT_COUNTS *LOG_FORMAT_REPEAT_MAX
#define LOG_FORMAT_IOVEC_MAX  LOG_FORMAT_FIELDS_MAX * 2 + 1

struct log_format_field {
	enum log_format_type f_type;
	struct iovec *f_iov;
};

struct log_format {
	char *line;

	struct iovec *iov;
	size_t iovec_nr;

	unsigned int f_mask;
	struct log_format_field *fields;
	size_t fields_nr;

	struct iovec values[LOG_FORMAT_COUNTS];
};

static struct log_format log_fmt = { 0 };
static long int iovec_max        = 0;

enum option_flag {
	OPT_SEND_TO_ALL   = (1 << 0), /* send message to all IPv4/IPv6 addresses */
	OPT_FORK          = (1 << 1), /* don't fork - don't run in daemon mode */
	OPT_COMPRESS      = (1 << 2), /* compress repeated messages flag */
	OPT_NET_HOPS      = (1 << 3), /* can we bounce syslog messages through an
	                               * intermediate host. */
	OPT_ACCEPT_REMOTE = (1 << 4), /* receive messages that come via UDP */
};

static unsigned options = 0;

static char LocalHostName[MAXHOSTNAMELEN + 1]; /* our hostname */
static const char *LocalDomain;                /* our local domain name */
static const char *emptystring   = "";
static int InetInuse             = 0;       /* non-zero if INET sockets are being used */
static unsigned int MarkInterval = 20 * 60; /* interval between marks in seconds */
#ifdef SYSLOG_INET6
static int family = PF_UNSPEC; /* protocol family (IPv4, IPv6 or both) */
#else
static int family = PF_INET; /* protocol family (IPv4 only) */
#endif
static time_t now           = 0;
static int DupesPending     = 0;    /* Number of unflushed duplicate messages */
static char **StripDomains  = NULL; /* these domains may be stripped before writing logs */
static char **LocalHosts    = NULL; /* these hosts are logged with their hostname */

static char *bind_addr   = NULL; /* bind UDP port to this interface only */
static char *server_user = NULL; /* user name to run server as */
static char *chroot_dir  = NULL; /* user name to run server as */

#ifndef errno
extern int errno;
#endif

/* Function prototypes. */
int main(int argc, char **argv);
size_t safe_strncpy(char *dest, const char *src, size_t size) SYSKLOGD_NONNULL((1, 2));
size_t safe_strncat(char *d, const char *s, size_t n) SYSKLOGD_NONNULL((1, 2));
char **crunch_list(char *list);
void usage(void) SYSLOGD_NORETURN();
void untty(void);
void printchopped(const struct sourceinfo *const, char *msg, size_t len, int fd);
void printline(const struct sourceinfo *const, char *msg);
void logmsg(unsigned int pri, const char *msg, const struct sourceinfo *const, int flags);
void clear_record_fields(struct log_format *log_fmt)
    SYSKLOGD_NONNULL((1));
void set_record_field(struct log_format *log_fmt, enum log_format_type name,
                      const char *value, ssize_t len)
    SYSKLOGD_NONNULL((1));
void fprintlog(register struct filed *f, const struct sourceinfo *const source,
               int flags, const char *msg);
void log_remote(struct filed *f, struct log_format *fmt, const struct sourceinfo *const from)
    SYSKLOGD_NONNULL((1, 2, 3));
void log_users(struct filed *f, struct log_format *fmt)
    SYSKLOGD_NONNULL((1, 2));
void log_locally(struct filed *f, struct log_format *fmt, int flags)
    SYSKLOGD_NONNULL((1, 2));
void endtty(int);
void wallmsg(register struct filed *f, struct log_format *log_fmt);
const char *cvtaddr(struct sockaddr_storage *f, unsigned int len);
const char *cvthname(struct sockaddr_storage *f, unsigned int len);
void flush_dups(void);
void flush_mark(void);
void debug_switch(int);
void logerror(const char *fmt, ...)
    SYSKLOGD_FORMAT((__printf__, 1, 2)) SYSKLOGD_NONNULL((1));
void die(int sig) SYSLOGD_NORETURN();
void doexit(int sig) SYSLOGD_NORETURN();
void init(void);
void event_dispatch(void) SYSLOGD_NORETURN();
void parse_config_line(const char *line, struct filed *f) SYSKLOGD_NONNULL((1, 2));
int parse_config_file(const char *filename) SYSKLOGD_NONNULL((1));
int decode(const char *name, const CODE *codetab) SYSKLOGD_NONNULL((1, 2));
const char *print_code_name(int val, const CODE *codetab) SYSKLOGD_NONNULL((2));
struct filed *allocate_log(void);
int set_log_format_field(struct log_format *log_fmt, size_t i, enum log_format_type t,
                         const char *s, size_t n)
    SYSKLOGD_NONNULL((1));
int parse_log_format(struct log_format *log_fmt, const char *s);
void free_log_format(struct log_format *fmt);
void calculate_digest(struct filed *f, struct log_format *log_fmt);
int set_nonblock_flag(int desc);
int create_unix_socket(const char *path, enum unixaf_option opt) SYSKLOGD_NONNULL((1));
ssize_t recv_withcred(int s, void *buf, size_t len, int flags, pid_t *pid, uid_t *uid, gid_t *gid);
int create_inet_sockets(void);
int drop_root(void);
void add_funix_dir(const char *dname) SYSKLOGD_NONNULL((1));
void set_internal_sinfo(struct sourceinfo *source) SYSKLOGD_NONNULL((1));
int set_input(enum input_type type, const char *name, int fd);
void free_files(void);
void free_inputs(void);
void set_pmask(int i, int pri, int flags, struct filed *f) SYSKLOGD_NONNULL((4));
char *textpri(unsigned int pri);

static inline int is_logger_initialized(struct log_format *fmt)
{
	return (fmt->line != NULL);
}

size_t safe_strncpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}

size_t safe_strncat(char *d, const char *s, size_t n)
{
	size_t l = strnlen(d, n);
	if (l == n)
		return l + strlen(s);
	return l + safe_strncpy(d + l, s, n - l);
}

int set_input(enum input_type type, const char *name, int fd)
{
	struct input *ptr = NULL;

	if (name) {
		for (ptr = inputs; ptr; ptr = ptr->next) {
			if (ptr->type == type && !strcmp(ptr->name, name))
				break;
		}
	}

	if (!ptr) {
		ptr = malloc(sizeof(*ptr));

		if (!ptr) {
			warn("unable to allocate more space");
			return -1;
		}
	}

	ptr->type = type;
	ptr->name = name;
	ptr->fd   = fd;
	ptr->next = inputs;

	inputs = ptr;

	return 0;
}

#ifdef SYSLOG_UNIXAF
int create_unix_socket(const char *path, enum unixaf_option option)
{
	struct sockaddr_un sunx;
	int fd;

	if (path[0] == '\0')
		return -1;

	if (option == UNIXAF_BIND)
		unlink(path);

	memset(&sunx, 0, sizeof(sunx));
	sunx.sun_family = AF_UNIX;
	safe_strncpy(sunx.sun_path, path, sizeof(sunx.sun_path));

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		logerror("cannot create %s: %m", path);
		goto err;
	}

	if (option == UNIXAF_BIND) {
		int passcred = 1;
		socklen_t sl = sizeof(passcred);

		if (bind(fd, (struct sockaddr *) &sunx, sizeof(sunx.sun_family) + strlen(sunx.sun_path)) < 0) {
			logerror("cannot bind to %s: %m", path);
			goto err;
		}

		if (chmod(path, 0666) < 0) {
			logerror("cannot change permissions of %s: %m", path);
			goto err;
		}

		setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred, sl);
	} else if (option == UNIXAF_CONNECT) {
		if (connect(fd, (struct sockaddr *) &sunx, sizeof(sunx.sun_family) + strlen(sunx.sun_path)) < 0) {
			logerror("cannot connect to %s: %m", path);
			goto err;
		}
	}

	return fd;
err:
	if (fd >= 0)
		close(fd);
	return -1;
}

ssize_t recv_withcred(int s, void *buf, size_t len, int flags,
                      pid_t *pid, uid_t *uid, gid_t *gid)
{
	struct cmsghdr *cmptr;
	struct msghdr m;
	struct iovec iov;
	char control[CMSG_SPACE(sizeof(struct ucred))];
	ssize_t rc;

	memset(&m, 0, sizeof(m));
	memset(control, 0, sizeof(control));

	iov.iov_base = buf;
	iov.iov_len  = len;

	m.msg_iov        = &iov;
	m.msg_iovlen     = 1;
	m.msg_control    = control;
	m.msg_controllen = sizeof(control);

	if ((rc = recvmsg(s, &m, flags)) < 0)
		return rc;

#ifdef SCM_CREDENTIALS
	if (!(m.msg_flags & MSG_CTRUNC) &&
	    (cmptr = (m.msg_controllen >= sizeof(struct cmsghdr)) ? CMSG_FIRSTHDR(&m) : NULL) &&
	    (cmptr->cmsg_level == SOL_SOCKET) &&
	    (cmptr->cmsg_type == SCM_CREDENTIALS)) {
		if (pid)
			*pid = ((struct ucred *) CMSG_DATA(cmptr))->pid;
		if (uid)
			*uid = ((struct ucred *) CMSG_DATA(cmptr))->uid;
		if (gid)
			*gid = ((struct ucred *) CMSG_DATA(cmptr))->gid;
	} else
#endif // SCM_CREDENTIALS
	{
		if (pid)
			*pid = (pid_t) -1;
		if (uid)
			*uid = (uid_t) -1;
		if (gid)
			*gid = (gid_t) -1;
	}

	return rc;
}
#endif // SYSLOG_UNIXAF

#ifdef SYSLOG_INET
int create_inet_sockets(void)
{
	struct addrinfo hints, *res, *r;
	int error, socks;
	int on = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_family   = family;
	hints.ai_socktype = SOCK_DGRAM;

	error = getaddrinfo(bind_addr, "syslog", &hints, &res);
	if (error) {
		logerror("network logging disabled (syslog/udp service unknown or address incompatible).");
		logerror("see syslogd(8) for details of whether and how to enable it.");
		logerror("%s", gai_strerror(error));
		return -1;
	}

	socks = 0; /* num of sockets */

	for (r = res; r; r = r->ai_next) {
		int s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (s < 0) {
			logerror("socket: %m");
			continue;
		}
		if (r->ai_family == AF_INET6) {
			if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
				logerror("setsockopt(IPV6_ONLY), suspending IPv6: %m");
				close(s);
				continue;
			}
		}
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			logerror("setsockopt(REUSEADDR), suspending inet: %m");
			close(s);
			continue;
		}
		/*
		 * We must not block on the network socket, in case a packet
		 * gets lost between select and recv, otherise the process
		 * will stall until the timeout, and other processes trying to
		 * log will also stall.
		 */
		if (set_nonblock_flag(s) < 0) {
			logerror("fcntl(O_NONBLOCK), suspending inet: %m");
			close(s);
			continue;
		}
		if (bind(s, r->ai_addr, r->ai_addrlen) < 0) {
			logerror("bind, suspending inet: %m");
			close(s);
			continue;
		}

		set_input(INPUT_INET, NULL, s);
		socks++;
	}
	if (res)
		freeaddrinfo(res);
	if (!socks)
		logerror("no valid sockets, suspending inet");
	return socks;
}
#endif // SYSLOG_INET

int set_nonblock_flag(int desc)
{
	int flags = fcntl(desc, F_GETFL, 0);

	if ((flags == -1) || (flags & O_NONBLOCK))
		return flags;

	return fcntl(desc, F_SETFL, flags | O_NONBLOCK);
}

int drop_root(void)
{
	struct passwd *pw;

	if (!(pw = getpwnam(server_user))) return -1;

	if (!pw->pw_uid) return -1;

	if (chroot_dir) {
		if (chdir(chroot_dir)) return -1;
		if (chroot(".")) return -1;
	}

	if (initgroups(server_user, pw->pw_gid)) return -1;
	if (setgid(pw->pw_gid)) return -1;
	if (setuid(pw->pw_uid)) return -1;

	return 0;
}

void add_funix_dir(const char *dname)
{
	DIR *dir;
	struct dirent *entry;

	if (chdir(dname)) {
		warnx("chdir: %s: %m", dname);
		return;
	}

	if (!(dir = opendir(".")))
		err(1, "opendir: %s", dname);

	while ((entry = readdir(dir))) {
		struct stat st;

		if (strchr(entry->d_name, '.'))
			continue;

		if (lstat(entry->d_name, &st))
			continue;

		if (S_ISLNK(st.st_mode)) {
			const char *name;
			char buf[MAXPATHLEN];
			ssize_t n = readlink(entry->d_name, buf, sizeof(buf));

			if ((n <= 0) || (n >= sizeof(buf)) || (buf[0] != '/'))
				continue;
			buf[n] = '\0';

			if (!(name = strdup(buf)))
				errx(1, "sorry, can't get enough memory, exiting.");

			set_input(INPUT_UNIX, name, -1);
		}
	}

	if (closedir(dir))
		warn("closedir: %s", dname);

	if (chdir("/") < 0)
		err(1, "chdir to / failed");
}

void event_dispatch(void)
{
	int i;
	ssize_t msglen;
	char line[MAXLINE + 1];

	time_t last_flush_dups = 0;
	time_t last_flush_mark = 0;

	for (;;) {
		struct epoll_event ev[128];
		int nfds;

		errno = 0;
		nfds  = epoll_wait(epoll_fd, ev, 128, 1000);

		if (nfds < 0 && errno != EINTR) {
			logerror("epoll_wait: %m");
			break;
		}

		time(&now);

		if (DupesPending > 0 && (now - last_flush_dups) >= TIMERINTVL) {
			last_flush_dups = now;
			flush_dups();
		}

		if (MarkInterval > 0 && (now - last_flush_mark) >= MarkInterval) {
			last_flush_mark = now;
			flush_mark();
		}

		for (i = 0; i < nfds; i++) {
			struct sourceinfo sinfo = { 0 };
			struct input *p = ev[i].data.ptr;
#ifdef SYSLOG_UNIXAF
			if (p->type == INPUT_UNIX) {
				memset(line, 0, sizeof(line));

				msglen = recv_withcred(p->fd, line, MAXLINE - 2, 0,
				                       &sinfo.pid, &sinfo.uid, &sinfo.gid);

				if (verbose)
					warnx("message from UNIX socket: #%d", p->fd);

				if (sinfo.uid == -1 || sinfo.gid == -1 || sinfo.pid == -1)
					logerror("error - credentials not provided");
				else
					sinfo.flags = SINFO_HAVECRED;

				if (msglen > 0) {
					sinfo.hostname = LocalHostName;
					printchopped(&sinfo, line, msglen + 2, p->fd);
				} else if (msglen < 0 && errno != EINTR) {
					logerror("recvfrom UNIX socket: %m");
				}
				continue;
			}
#endif
#ifdef SYSLOG_INET
			if (p->type == INPUT_INET) {
				struct sockaddr_storage frominet;
				socklen_t len;

				len = sizeof(frominet);

				memset(line, 0, sizeof(line));

				msglen = recvfrom(p->fd, line, MAXLINE - 2, 0,
				                  (struct sockaddr *) &frominet, &len);
				if (verbose) {
					const char *addr = cvtaddr(&frominet, len);
					if (verbose)
						warnx("message from inetd socket: host: %s", addr);
				}

				if (msglen > 0) {
					/* Note that if cvthname() returns NULL then
					   we shouldn't attempt to log the line -- jch */
					sinfo.hostname = (char *) cvthname(&frominet, len);
					printchopped(&sinfo, line, msglen + 2, p->fd);
				} else if (msglen < 0 && errno != EINTR && errno != EAGAIN) {
					logerror("recvfrom INET socket: %m");
					/* should be harmless now that we set
					 * BSDCOMPAT on the socket */
					sleep(1);
				}
				continue;
			}
#endif
			if (p->type == INPUT_SIGNALFD) {
				int status;
				struct signalfd_siginfo fdsi;

				if (read(p->fd, &fdsi, sizeof(fdsi)) != sizeof(fdsi)) {
					logerror("unable to read signal info");
					continue;
				}

				if (verbose)
					warnx("received signal #%d (%s).",
							fdsi.ssi_signo,
							strsignal(fdsi.ssi_signo));

				switch (fdsi.ssi_signo) {
					case SIGINT:
					case SIGQUIT:
						if (!(options & OPT_FORK))
							die(fdsi.ssi_signo);
						break;
					case SIGTERM:
						die(fdsi.ssi_signo);
						break;
					case SIGHUP:
						if (verbose)
							warnx("reloading syslogd.");
						init();
						break;
					case SIGCHLD:
						if (waitpid(-1, &status, 0) < 0)
							logerror("waitpid: %m");
						break;
					default:
						// ignore
						break;
				}

				continue;
			}
			logerror("Drop unhandled type of input descriptor #%d (%s)",
			         p->fd, print_code_name(p->type, InputTypeNames));
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p->fd, NULL);
			close(p->fd);
			p->fd = -1;
		}
	}
	exit(1);
}

int main(int argc, char **argv)
{
	int num_fds, i, fd, ch;
	pid_t ppid = getpid();

	extern int optind;
	extern char *optarg;
	const char *funix_dir = "/etc/syslog.d";
	const char *devlog    = _PATH_LOG;

	if (chdir("/") < 0)
		err(1, "chdir to / failed");

	options |= OPT_COMPRESS | OPT_FORK;

	while ((ch = getopt(argc, argv, "46Aa:cdhf:i:j:l:m:np:P:rs:u:v")) != EOF)
		switch ((char) ch) {
			case '4':
				family = PF_INET;
				break;
#ifdef SYSLOG_INET6
			case '6':
				family = PF_INET6;
				break;
#endif
			case 'A':
				options |= OPT_SEND_TO_ALL;
				break;
			case 'a':
				set_input(INPUT_UNIX, optarg, -1);
				break;
			case 'c': /* don't compress repeated messages */
				options &= ~OPT_COMPRESS;
				break;
			case 'd': /* verbosity */
				verbose++;
				break;
			case 'f': /* configuration file */
				ConfFile = optarg;
				break;
			case 'h':
				options |= OPT_NET_HOPS;
				break;
			case 'i':
				if (bind_addr) {
					warnx("only one -i argument allowed, "
					      "the first one is taken.");
					break;
				}
				bind_addr = optarg;
				break;
			case 'j':
				chroot_dir = optarg;
				break;
			case 'l':
				if (LocalHosts) {
					warnx("only one -l argument allowed, "
					      "the first one is taken.");
					break;
				}
				LocalHosts = crunch_list(optarg);
				break;
			case 'm': /* mark interval */
				MarkInterval = atoi(optarg) * 60;
				break;
			case 'n': /* don't fork */
				options &= ~OPT_FORK;
				break;
			case 'p': /* path to regular log socket */
				devlog = optarg;
				break;
			case 'P':
				funix_dir = optarg;
				break;
			case 'r': /* accept remote messages */
				options |= OPT_ACCEPT_REMOTE;
				break;
			case 's':
				if (StripDomains) {
					warnx("only one -s argument allowed,"
					      "the first one is taken.");
					break;
				}
				StripDomains = crunch_list(optarg);
				break;
			case 'u':
				server_user = optarg;
				break;
			case 'v':
				printf("syslogd %s\n", VERSION);
				exit(0);
			case '?':
			default:
				usage();
		}
	if ((argc -= optind))
		usage();

	if (chroot_dir && !server_user)
		errx(1, "'-j' is only valid with '-u'");

	set_input(INPUT_UNIX, devlog, -1);

	if (funix_dir && *funix_dir)
		add_funix_dir(funix_dir);

	if (parse_log_format(&log_fmt, "%t %h (uid=%u) %m") < 0)
		exit(1);

	if ((options & OPT_FORK)) {
		pid_t pid;

		if (verbose)
			warnx("checking pidfile.");

		if (check_pid(PidFile))
			errx(1, "already running.");

		if ((fd = open(_PATH_DEVNULL, O_RDWR)) < 0)
			err(1, "open: %s", _PATH_DEVNULL);

		signal(SIGTERM, doexit);
		if ((pid = fork()) == -1) {
			err(1, "fork failed.");
		} else if (pid) {
			/*
			 * Parent process
			 */
			sleep(300);
			/*
			 * Not reached unless something major went wrong.  5
			 * minutes should be a fair amount of time to wait.
			 * Please note that this procedure is important since
			 * the father must not exit before syslogd isn't
			 * initialized or the klogd won't be able to flush its
			 * logs.  -Joey
			 */
			exit(1);
		}
		signal(SIGTERM, SIG_DFL);
		num_fds = getdtablesize();
		if (dup2(fd, 0) != 0 || dup2(fd, 1) != 1 || dup2(fd, 2) != 2)
			err(1, "dup2 failed");

		for (i = 3; i < num_fds; i++)
			close(i);
		untty();

		if (verbose)
			warnx("writing pidfile.");

		if (!check_pid(PidFile)) {
			if (!write_pid(PidFile)) {
				if (verbose)
					warnx("can't write pid.");
				if (getpid() != ppid)
					kill(ppid, SIGTERM);
				exit(1);
			}
		} else {
			if (verbose)
				warnx("pidfile (and pid) already exist.");
			if (getpid() != ppid)
				kill(ppid, SIGTERM);
			exit(1);
		}
	}

	/*
	 * Prepare console output. The file descriptor will be opened by init()
	 * if needed.
	 */
	consfile.f_type = F_CONSOLE;
	safe_strncpy(consfile.f_un.f_fname, _PATH_CONSOLE, sizeof(consfile.f_un.f_fname));

	/* Initialization is done by init() */
	safe_strncpy(LocalHostName, emptystring, sizeof(LocalHostName));
	LocalDomain = emptystring;

	sigfillset(&signal_mask);
	sigprocmask(SIG_SETMASK, &signal_mask, NULL);

	/* Create a partial message table for all file descriptors. */
	num_fds = getdtablesize();

	if (verbose)
		warnx("allocated parts table for %d file descriptors.", num_fds);

	if (!(parts = malloc(num_fds * sizeof(char *)))) {
		logerror("cannot allocate memory for message parts table.");

		if (getpid() != ppid)
			kill(ppid, SIGTERM);

		die(0);
	}
	for (i = 0; i < num_fds; ++i)
		parts[i] = NULL;

	if (verbose)
		warnx("starting.");

	init();

	/*
	 * Send a signal to the parent to it can terminate.
	 */
	if (getpid() != ppid)
		kill(ppid, SIGTERM);

	if (server_user && drop_root()) {
		if (verbose)
			warnx("failed to drop root.");
		exit(1);
	}

	event_dispatch();
}

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

void untty(void)
{
	if ((options & OPT_FORK)) {
		setsid();
	}
}

/*
 * Parse the line to make sure that the msg is not a composite of more
 * than one message.
 */

void printchopped(const struct sourceinfo *const source, char *msg, size_t len, int fd)
{
	auto size_t ptlngth;

	auto char *start = msg,
	          *p,
	          *end,
	          tmpline[MAXLINE + 1];

	if (verbose)
		warnx("message length: %lu, File descriptor: %d.", len, fd);

	tmpline[0] = '\0';
	if (parts[fd] != NULL) {
		if (verbose)
			warnx("including part from messages.");

		safe_strncpy(tmpline, parts[fd], sizeof(tmpline));
		free(parts[fd]);
		parts[fd] = NULL;
		if ((strlen(msg) + strlen(tmpline)) > MAXLINE) {
			logerror("cannot glue message parts together");
			printline(source, tmpline);
			start = msg;
		} else {
			if (verbose) {
				warnx("previous: %s", tmpline);
				warnx("next: %s", msg);
			}
			safe_strncat(tmpline, msg, sizeof(tmpline)); /* length checked above */
			printline(source, tmpline);
			if ((strlen(msg) + 1) == len)
				return;
			else
				start = strchr(msg, '\0') + 1;
		}
	}

	if (msg[len - 1] != '\0') {
		msg[len] = '\0';
		for (p = msg + len - 1; *p != '\0' && p > msg;)
			--p;
		if (*p == '\0') p++;
		ptlngth = strlen(p);
		if ((parts[fd] = malloc(ptlngth + 1)) == NULL)
			logerror("cannot allocate memory for message part.");
		else {
			safe_strncpy(parts[fd], p, ptlngth + 1);
			if (verbose)
				warnx("saving partial msg: %s", parts[fd]);
			memset(p, '\0', ptlngth);
		}
	}

	do {
		end = strchr(start + 1, '\0');
		printline(source, start);
		start = end + 1;
	} while (*start != '\0');

	return;
}

/*
 * Take a raw input line, decode the message, and print the message
 * on the appropriate log files.
 */

void printline(const struct sourceinfo *const source, char *msg)
{
	register char *p, *q;
	register char c;
	char line[MAXLINE + 1];
	unsigned int pri; // Valid Priority values are 0-191
	int prilen = 0;   // Track Priority value string len
	size_t msglen;

	/* test for special codes */
	msglen = strlen(msg);
	pri    = DEFUPRI;
	p      = msg;

	if (*p == '<') {
		pri = 0;
		while (--msglen > 0 && isdigit((unsigned char) *++p) &&
		       pri <= MAX_PRI) {
			pri = 10 * pri + (*p - '0');
			prilen++;
		}
		if (*p == '>' && prilen)
			++p;
		else {
			pri = DEFUPRI;
			p   = msg;
		}
	}

	if ((pri & ~(LOG_FACMASK | LOG_PRIMASK)) || (pri > MAX_PRI)) {
		pri = DEFUPRI;
		p   = msg;
	}

	memset(line, 0, sizeof(line));
	q = line;
	while ((c = *p++) && q < &line[sizeof(line) - 4]) {
		if (c == '\n' || c == 127)
			*q++ = ' ';
		else if (c < 040) {
			*q++ = '^';
			*q++ = c ^ 0100;
		} else
			*q++ = c;
	}
	*q = '\0';

	logmsg(pri, line, source, SYNC_FILE);
	return;
}

/*
 * Decode a priority into textual information like auth.emerg.
 */
char *textpri(unsigned int pri)
{
	static char res[20];
	const CODE *c_pri, *c_fac;

	for (c_fac = bb_facilitynames; c_fac->c_name && !(c_fac->c_val == LOG_FAC(pri) << 3); c_fac++)
		;
	for (c_pri = bb_prioritynames; c_pri->c_name && !(c_pri->c_val == LOG_PRI(pri)); c_pri++)
		;

	snprintf(res, sizeof(res), "%s.%s<%u>", c_fac->c_name, c_pri->c_name, pri);

	return res;
}

/*
 * Log a message to the appropriate log files, users, etc. based on
 * the priority.
 */

void logmsg(unsigned int pri, const char *msg, const struct sourceinfo *const from, int flags)
{
	struct filed *f;
	int fac, prilev;
	size_t msglen;
	char newmsg[MAXLINE + 1];

	if (verbose)
		warnx("logmsg: %s, flags %x, from %s, msg %s", textpri(pri), flags, from->hostname, msg);

	/*
	 * Check to see if msg looks non-standard.
	 *
	 * A message looks like
	 * Nov 17 11:42:33 CRON[
	 * 01234567890123456
	 *    ^  ^  ^  ^  ^
	 *
	 * Remote messages are not accompanied by a timestamp.
	 * Local messages are accompanied by a timestamp (program's timezone)
	 */
	msglen = strlen(msg);
	if (!(msglen < 16 || msg[3] != ' ' || msg[6] != ' ' ||
	      msg[9] != ':' || msg[12] != ':' || msg[15] != ' ')) {
		msg += 16;
		msglen -= 16;
	}

	time(&now);

	/* extract facility and priority level */
	fac    = LOG_FAC(pri);
	prilev = LOG_PRI(pri);

	/*
	 * If we have credentials info, let's validate program name and pid.
	 * We follow RFC 3164 section 4.1 and take process name (TAG) to
	 * be 32 characters or less, terminated with ':' or '[',
	 * but, unlike stated in the document, we tolerate non-alphanumeric
	 * characters (which restriction is probably just a mistake,
	 * as '-' sign is quite common) and spaces (LPRng daemons are said
	 * to have space in the name).
	 */
	if (from->flags & SINFO_HAVECRED) { /* XXX: should log error on no creds? */
		char tag[32 + 10];          /* rfc3164 tag+brackets+pid+colon+space+0 */
		char *p;
		char *oldpid;

		newmsg[0] = '\0';

		tag[0] = '\0';
		safe_strncat(tag, msg, sizeof(tag));

		p = strchr(tag, ':');
		if (!(oldpid = strchr(tag, '[')) || (p && p < oldpid)) {
			/* We do not have valid pid in tag, skip to tag end */
			if (p || (p = strchr(tag, ' '))) {
				*p = '\0';
				msg += (p + 1 - tag);
				while (*msg == ' ')
					msg++;
				/* ..and add one */
				snprintf(newmsg, sizeof(newmsg),
				         "%s[%u]: ", tag, from->pid);
			} else {
				/* Yes, it is safe to call logerror() from this
				   part of logmsg().  Complain about tag being
				   invalid */
				logerror("credentials processing failed -- "
				         "received malformed message");
				return;
			}
		} else {
			/* As we have pid, validate it */
			if ((p = strchr(tag, ']'))) {
				*p = '\0';
				msg += (p + 1 - tag);
				if (*msg == ':')
					msg++;
				while (*msg == ' ')
					msg++;
			} else {
				logerror("credentials processing failed -- "
				         "received malformed message");
				return;
			}
			*oldpid++ = '\0';
			/* XXX: We could use strtoul() here for full
			   error checking. */
			if ((pid_t) atoi(oldpid) != from->pid) {
				logerror("malformed or spoofed pid detected!");
				snprintf(newmsg, sizeof(newmsg),
				         "%s[%s!=%u]: ",
				         tag, oldpid, from->pid);
			} else
				snprintf(newmsg, sizeof(newmsg),
				         "%s[%u]: ", tag, from->pid);
		}
		/* We may place group membership check here */
		/* XXX: Silent truncation is possible */
		safe_strncat(newmsg, msg, sizeof(newmsg) - strlen(newmsg));
		msg    = newmsg;
		msglen = strlen(msg);
	}

	/* log the message to the particular outputs */
	if (!files) {
		f = &consfile;

		f->f_file = open(f->f_un.f_fname, O_WRONLY | O_NOCTTY);

		if (f->f_file >= 0) {
			untty();
			fprintlog(f, from, flags, msg);
			close(f->f_file);
			f->f_file = -1;
		}
		return;
	}

	for (f = files; f; f = f->next) {
		/* skip messages that are incorrect priority */
		if ((f->f_pmask[fac] == TABLE_NOPRI) ||
		    ((f->f_pmask[fac] & (1 << prilev)) == 0))
			continue;

		if (f->f_type == F_CONSOLE && (flags & IGN_CONS))
			continue;

		/* don't output marks to recently written files */
		if ((flags & MARK) && (now - f->f_time) < MarkInterval / 2)
			continue;

		/*
		 * suppress duplicate lines to this file
		 */
		if ((options & OPT_COMPRESS) && (flags & MARK) == 0 && msglen == f->f_prevlen &&
		    !strcmp(msg, f->f_prevline) &&
		    !strcmp(from->hostname, f->f_prevhost)) {
			f->f_lasttime = now;
			f->f_prevcount++;

			if (verbose)
				warnx("msg repeated %d times, %ld sec of %ld.",
				      f->f_prevcount, now - f->f_time,
				      repeatinterval[f->f_repeatcount]);

			if (f->f_prevcount == 1)
				DupesPending++;

			/*
			 * If flush_dups would have logged this by now,
			 * flush it now (so we don't hold isolated messages),
			 * but back off so we'll flush less often
			 * in the future.
			 */
			if (now > REPEATTIME(f)) {
				fprintlog(f, from, flags, NULL);
				BACKOFF(f);
			}
		} else {
			/* new line, save it */
			if (f->f_prevcount) {
				fprintlog(f, from, 0, NULL);
				DupesPending--;
			}

			f->f_prevpri     = pri;
			f->f_lasttime    = now;
			f->f_repeatcount = 0;

			safe_strncpy(f->f_prevhost, from->hostname, sizeof(f->f_prevhost));

			if (msglen < MAXSVLINE) {
				f->f_prevlen = msglen;
				safe_strncpy(f->f_prevline, msg, sizeof(f->f_prevline));
				fprintlog(f, from, flags, NULL);
			} else {
				f->f_prevline[0] = 0;
				f->f_prevlen     = 0;
				fprintlog(f, from, flags, msg);
			}
		}
	}
}

void set_record_field(struct log_format *fmt,
                      enum log_format_type name, const char *value, ssize_t len)
{
	size_t iov_len = len == -1 ? strlen(value) : len;

	fmt->values[name].iov_base = (void *) value;
	fmt->values[name].iov_len  = iov_len;

	if (!(fmt->f_mask | (1U << name)))
		return;

	for (int i = 0; i < LOG_FORMAT_FIELDS_MAX && fmt->fields[i].f_iov; i++) {
		if (fmt->fields[i].f_type == name) {
			fmt->fields[i].f_iov->iov_base = (void *) value;
			fmt->fields[i].f_iov->iov_len  = iov_len;
		}
	}
}

void clear_record_fields(struct log_format *fmt)
{
	for (int i = 0; i < LOG_FORMAT_FIELDS_MAX && fmt->fields[i].f_iov; i++) {
		fmt->fields[i].f_iov->iov_base = NULL;
		fmt->fields[i].f_iov->iov_len  = 0;
	}
	for (int i = 0; i < LOG_FORMAT_COUNTS; i++) {
		fmt->values[i].iov_base = NULL;
		fmt->values[i].iov_len  = 0;
	}
}

void calculate_digest(struct filed *f, struct log_format *fmt)
{
	int i, n;
	unsigned char digest[HASH_RAWSZ];
	hash_ctx_t hash_ctx;

	if (!(fmt->f_mask | (1 << LOG_FORMAT_HASH)))
		return;

	digest[0] = 0;

	hash_init(&hash_ctx);
	for (i = 0; i < LOG_FORMAT_IOVEC_MAX; i++)
		hash_update(&hash_ctx, fmt->iov[i].iov_base, fmt->iov[i].iov_len);
	hash_final(digest, &hash_ctx);

	safe_strncpy(f->f_prevhash, HASH_NAME, sizeof(f->f_prevhash));
	n = HASH_NAMESZ;

	safe_strncpy(f->f_prevhash + n, ":", sizeof(f->f_prevhash) - n);
	n += 1;

	for (i = 0; i < HASH_RAWSZ; i++) {
		snprintf(f->f_prevhash + n, sizeof(f->f_prevhash) - n, "%02x", digest[i]);
		n += 2;
	}
	f->f_prevhash[n] = 0;
	return;
}

void log_remote(struct filed *f, struct log_format *fmt, const struct sourceinfo *const from)
{
#ifdef SYSLOG_INET
	size_t l;
	char line[MAXLINE + 1];
	time_t fwd_suspend;
	struct addrinfo hints, *ai;
	int err;
again:
	if (verbose)
		warnx("log to remote server %s %s", TypeNames[f->f_type], f->f_un.f_forw.f_hname);

	if (f->f_type == F_FORW_SUSP) {
		fwd_suspend = time(NULL) - f->f_time;

		if (fwd_suspend >= INET_SUSPEND_TIME) {
			if (verbose)
				warnx("forwarding suspension over, retrying FORW");
			f->f_type = F_FORW;
			goto again;
		}

		if (verbose)
			warnx("forwarding suspension not over, time left: %ld.",
			      INET_SUSPEND_TIME - fwd_suspend);
		return;
	}

	/*
	 * The trick is to wait some time, then retry to get the
	 * address. If that fails retry x times and then give up.
	 *
	 * You'll run into this problem mostly if the name server you
	 * need for resolving the address is on the same machine, but
	 * is started after syslogd.
	 */
	if (f->f_type == F_FORW_UNKN) {
		fwd_suspend = time(NULL) - f->f_time;

		if (fwd_suspend >= INET_SUSPEND_TIME) {
			if (verbose)
				warnx("forwarding suspension to unknown over, retrying.");

			memset(&hints, 0, sizeof(hints));
			hints.ai_family   = family;
			hints.ai_socktype = SOCK_DGRAM;

			if ((err = getaddrinfo(f->f_un.f_forw.f_hname, "syslog", &hints, &ai))) {
				if (verbose) {
					warnx("failure: %s", gai_strerror(err));
					warnx("retries: %d", f->f_prevcount);
				}
				if (--f->f_prevcount < 0) {
					if (verbose)
						warnx("giving up.");
					f->f_type = F_UNUSED;
				} else {
					if (verbose)
						warnx("left retries: %d", f->f_prevcount);
				}
				return;
			}

			if (verbose)
				warnx("host %s found, resuming.", f->f_un.f_forw.f_hname);
			f->f_un.f_forw.f_addr = ai;
			f->f_prevcount        = 0;
			f->f_type             = F_FORW;
			goto again;
		}

		if (verbose)
			warnx("forwarding suspension not over, time left: %ld",
			      INET_SUSPEND_TIME - fwd_suspend);
		return;
	}

	if (f->f_type != F_FORW)
		return;

	/*
	 * Don't send any message to a remote host if it
	 * already comes from one. (we don't care 'bout who
	 * sent the message, we don't send it anyway)  -Joey
	 */
	if (strcmp(from->hostname, LocalHostName) && !(options & OPT_NET_HOPS)) {
		if (verbose)
			warnx("not sending message to remote.");
		return;
	}

	if (!InetInuse)
		return;

	f->f_time = now;

	snprintf(line, sizeof(line), "<%u>%.*s", f->f_prevpri,
	         (int) fmt->values[LOG_FORMAT_MSG].iov_len,
	         (char *) fmt->values[LOG_FORMAT_MSG].iov_base);

	if ((l = strlen(line)) > MAXLINE)
		l = MAXLINE;

	err = -1;
	for (ai = f->f_un.f_forw.f_addr; ai; ai = ai->ai_next) {
		for (struct input *p = inputs; p; p = p->next) {
			ssize_t lsent;

			if (p->fd == -1 || p->type != INPUT_INET)
				continue;

			lsent = sendto(p->fd, line, l, 0, ai->ai_addr, ai->ai_addrlen);

			if (lsent == l) {
				err = -1;
				break;
			}
			err = errno;
		}
		if (err == -1 && !(options & OPT_SEND_TO_ALL))
			break;
	}

	if (err != -1) {
		f->f_type = F_FORW_SUSP;

		errno = err;
		logerror("sendto: %m");
	}
#endif
}

void log_locally(struct filed *f, struct log_format *fmt, int flags)
{
	if (f->f_type == F_CONSOLE) {
		f->f_time = now;

		if (flags & IGN_CONS) {
			if (verbose)
				warnx("log locally %s %s (ignored)",
				      TypeNames[f->f_type], f->f_un.f_fname);
			return;
		}
	}

	f->f_time = now;

	if (verbose)
		warnx("log locally %s %s", TypeNames[f->f_type], f->f_un.f_fname);

	if (f->f_type == F_TTY || f->f_type == F_CONSOLE) {
		set_record_field(fmt, LOG_FORMAT_EOL, "\r\n", 2);
	} else {
		set_record_field(fmt, LOG_FORMAT_EOL, "\n", 1);
	}
again:
	/*
	 * f->f_file == -1 is an indicator that we couldn't
	 * open the file at startup.
	 */
	if (f->f_file == -1)
		return;

	calculate_digest(f, fmt);

	if (writev(f->f_file, fmt->iov, LOG_FORMAT_IOVEC_MAX) < 0) {
		int e = errno;

		/* If a named pipe is full, just ignore it for now */
		if ((f->f_type == F_PIPE || f->f_type == F_TTY || f->f_type == F_UNIXAF) && e == EAGAIN)
			return;

		/*
		 * If the filesystem is filled up, just ignore
		 * it for now and continue writing when
		 * possible
		 */
		if (f->f_type == F_FILE && e == ENOSPC)
			return;

		close(f->f_file);

		if ((f->f_type == F_TTY || f->f_type == F_CONSOLE) && e == EIO) {
			f->f_file = open(f->f_un.f_fname, O_WRONLY | O_APPEND | O_NOCTTY);

			if (f->f_file >= 0) {
				if (f->f_type == F_TTY)
					set_nonblock_flag(f->f_file);
				untty();
				goto again;
			}

			f->f_type = F_UNUSED;

			logerror("open: %s: %m", f->f_un.f_fname);
		} else {
			f->f_type = F_UNUSED;

			errno = e;
			logerror("writev: %s: %m", f->f_un.f_fname);
		}
		return;
	}

	if (f->f_type == F_FILE && (f->f_flags & SYNC_FILE))
		fsync(f->f_file);
}

void log_users(struct filed *f, struct log_format *fmt)
{
	if (verbose)
		warnx("log to logged in users %s", TypeNames[f->f_type]);

	f->f_time = now;
	set_record_field(fmt, LOG_FORMAT_EOL, "\r\n", 2);
	calculate_digest(f, fmt);
	wallmsg(f, fmt);
}

void fprintlog(struct filed *f, const struct sourceinfo *const from,
               int flags, const char *msg)
{
	char s_uid[20], s_gid[20], s_pid[20], f_lasttime[26];

	clear_record_fields(&log_fmt);

	/*
	 * "Wed Jun 30 21:49:08 1993\n"
	 *  012345677890123456789
	 *      01234567890123456
	 *      ^              ^
	 */
	ctime_r(&f->f_lasttime, f_lasttime);

	set_record_field(&log_fmt, LOG_FORMAT_TIME, f_lasttime + 4, 15);
	set_record_field(&log_fmt, LOG_FORMAT_HOST, f->f_prevhost, -1);
	set_record_field(&log_fmt, LOG_FORMAT_HASH, f->f_prevhash, -1);

	snprintf(s_uid, sizeof(s_uid), "%d", from->uid);
	set_record_field(&log_fmt, LOG_FORMAT_UID, s_uid, -1);

	snprintf(s_gid, sizeof(s_gid), "%d", from->gid);
	set_record_field(&log_fmt, LOG_FORMAT_GID, s_gid, -1);

	snprintf(s_pid, sizeof(s_pid), "%d", from->pid);
	set_record_field(&log_fmt, LOG_FORMAT_PID, s_pid, -1);

	if (msg) {
		set_record_field(&log_fmt, LOG_FORMAT_MSG, msg, -1);
	} else if (f->f_prevcount > 1) {
		char repbuf[80];
		snprintf(repbuf, sizeof(repbuf), "last message repeated %d times",
		         f->f_prevcount);
		set_record_field(&log_fmt, LOG_FORMAT_MSG, repbuf, -1);
	} else {
		set_record_field(&log_fmt, LOG_FORMAT_MSG, f->f_prevline, f->f_prevlen);
	}

	switch (f->f_type) {
		case F_UNUSED:
			f->f_time = now;
			break;
		case F_FORW_SUSP:
		case F_FORW_UNKN:
		case F_FORW:
			log_remote(f, &log_fmt, from);
			break;
		case F_CONSOLE:
		case F_TTY:
		case F_FILE:
		case F_PIPE:
		case F_UNIXAF:
			log_locally(f, &log_fmt, flags);
			break;
		case F_USERS:
		case F_WALL:
			log_users(f, &log_fmt);
			break;
	}

	if (f->f_type != F_FORW_UNKN)
		f->f_prevcount = 0;
}

static jmp_buf ttybuf;

void endtty(int sig)
{
	longjmp(ttybuf, 1);
}

/*
 *  WALLMSG -- Write a message to the world at large
 *
 *	Write the specified message to either the entire
 *	world, or a list of approved users.
 */
void wallmsg(struct filed *f, struct log_format *fmt)
{
	char p[sizeof(_PATH_DEV) + UNAMESZ];
	register int i;
	int ttyf;
	static int reenter = 0;
	struct utmp ut;
	struct utmp *uptr;
	char greetings[200];

	if (reenter++)
		return;

	/* open the user login file */
	setutent();

	/*
	 * Might as well fork instead of using nonblocking I/O
	 * and doing notty().
	 */
	if (fork() == 0) {
		close(signal_fd);

		signal(SIGTERM, SIG_DFL);
		alarm(0);

		if (f->f_type == F_WALL) {
			snprintf(greetings, sizeof(greetings),
			         "\r\n\7Message from syslogd@%.*s at %.24s ...\r\n",
			         (int) fmt->values[LOG_FORMAT_HOST].iov_len,
			         (char *) fmt->values[LOG_FORMAT_HOST].iov_base,
			         ctime(&now));

			set_record_field(fmt, LOG_FORMAT_BOL, greetings, -1);
		}

		/* scan the user login file */
		while ((uptr = getutent())) {
			memcpy(&ut, uptr, sizeof(ut));
			/* is this slot used? */
			if (ut.ut_name[0] == '\0')
				continue;
			if (ut.ut_type != USER_PROCESS)
				continue;
			if (!(strcmp(ut.ut_name, "LOGIN"))) /* paranoia */
				continue;

			/* should we send the message to this user? */
			if (f->f_type == F_USERS) {
				for (i = 0; i < MAXUNAMES; i++) {
					if (!f->f_un.f_uname[i][0]) {
						i = MAXUNAMES;
						break;
					}
					if (!strncmp(f->f_un.f_uname[i], ut.ut_name, UNAMESZ))
						break;
				}
				if (i >= MAXUNAMES)
					continue;
			}

			/* compute the device name */
			safe_strncpy(p, _PATH_DEV, sizeof(p));
			strncat(p, ut.ut_line, UNAMESZ);

			if (setjmp(ttybuf) == 0) {
				signal(SIGALRM, endtty);
				alarm(15);
				/* open the terminal */
				ttyf = open(p, O_WRONLY | O_NOCTTY);
				if (ttyf >= 0) {
					struct stat statb;

					if (!fstat(ttyf, &statb) && (statb.st_mode & S_IWRITE)) {
						if (writev(ttyf, fmt->iov, LOG_FORMAT_IOVEC_MAX) < 0)
							errno = 0; /* ignore */
					}
					close(ttyf);
					ttyf = -1;
				}
			}
			alarm(0);
		}
		exit(0);
	}
	/* close the user login file */
	endutent();
	reenter = 0;
}

const char *cvtaddr(struct sockaddr_storage *f, unsigned int len)
{
	static char ip[NI_MAXHOST];

	if (getnameinfo((struct sockaddr *) f, len,
	                ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
		return "???";
	return ip;
}

/*
 * Return a printable representation of a host address.
 *
 * Here we could check if the host is permitted to send us syslog
 * messages.  We just have to check the hostname we're about to return
 * and compared it (case-insensitively) to a blacklist or whitelist.
 * Callers of cvthname() need to know that if NULL is returned then
 * the host is to be ignored.
 */
const char *cvthname(struct sockaddr_storage *f, unsigned int len)
{
	static char hname[NI_MAXHOST];
	int error;
	register char *p;
	int count;

	if ((error = getnameinfo((struct sockaddr *) f, len,
	                         hname, NI_MAXHOST, NULL, 0, NI_NAMEREQD))) {
		if (verbose)
			warnx("host name for your address (%s) unknown: %s",
			      hname, gai_strerror(error));
		if ((error = getnameinfo((struct sockaddr *) f, len,
		                         hname, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))) {
			if (verbose)
				warnx("malformed from address: %s", gai_strerror(error));
			return "???";
		}
		return hname;
	}
	/*
	 * Convert to lower case, just like LocalDomain above
	 */
	for (p = hname; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);

	/*
	 * Notice that the string still contains the fqdn, but your
	 * hostname and domain are separated by a '\0'.
	 */
	if ((p = strchr(hname, '.'))) {
		if (strcmp(p + 1, LocalDomain) == 0) {
			*p = '\0';
			return (hname);
		} else {
			if (StripDomains) {
				count = 0;
				while (StripDomains[count]) {
					if (strcmp(p + 1, StripDomains[count]) == 0) {
						*p = '\0';
						return (hname);
					}
					count++;
				}
			}
			if (LocalHosts) {
				count = 0;
				while (LocalHosts[count]) {
					if (!strcmp(hname, LocalHosts[count])) {
						*p = '\0';
						return (hname);
					}
					count++;
				}
			}
		}
	}

	return (hname);
}

void set_internal_sinfo(struct sourceinfo *source)
{
	memset(source, '\0', sizeof(*source));

	source->flags    = SINFO_ISINTERNAL;
	source->hostname = LocalHostName;
	source->uid      = geteuid();
	source->gid      = getegid();
	source->pid      = getpid();
}

void flush_dups(void)
{
	struct sourceinfo source;
	set_internal_sinfo(&source);

	if (verbose)
		warnx("flush duplicate messages.");

	for (struct filed *f = files; f; f = f->next) {
		if (f->f_prevcount && now >= REPEATTIME(f)) {
			if (verbose)
				warnx("flush %s: repeated %d times, %ld sec.",
				      TypeNames[f->f_type], f->f_prevcount,
				      repeatinterval[f->f_repeatcount]);
			fprintlog(f, &source, 0, NULL);
			BACKOFF(f);
			DupesPending--;
		}
	}
}

void flush_mark(void)
{
	struct sourceinfo source;
	set_internal_sinfo(&source);
	logmsg(LOG_MARK | LOG_INFO, "-- MARK --", &source, MARK);
}

/*
 * Print syslogd errors some place.
 */
void logerror(const char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZ];
	struct sourceinfo source;
	int sv_errno = errno;

	safe_strncpy(buf, "syslogd: ", sizeof(buf));

	va_start(ap, fmt);
	errno = sv_errno;
	vsnprintf(buf + 9, sizeof(buf) - 9, fmt, ap);
	va_end(ap);

	if (verbose)
		warnx("%s", buf + 9);

	if (!is_logger_initialized(&log_fmt)) {
		fputs(buf, stderr);
		errno = 0;
		return;
	}

	set_internal_sinfo(&source);

	logmsg(LOG_SYSLOG | LOG_ERR, buf, &source, 0);
	errno = 0;
	return;
}

void die(int sig)
{
	struct sourceinfo source;

	set_internal_sinfo(&source);

	if (sig) {
		char buf[100];
		if (verbose)
			warnx("exiting on signal %d", sig);
		snprintf(buf, sizeof(buf), "exiting on signal %d", sig);
		errno = 0;
		logmsg(LOG_SYSLOG | LOG_INFO, buf, &source, 0);
	}

	close(epoll_fd);

	free_files();
	free_inputs();
	free_log_format(&log_fmt);
	free(parts);

	remove_pid(PidFile);

	exit(0);
}

/*
 * Signal handler to terminate the parent process.
 */
void doexit(int sig)
{
	_exit(0);
}

/*
 *  INIT -- Initialize syslogd from configuration table
 */
void init(void)
{
	register int i, lognum;
	register struct filed *f;
	register char *p;
	register unsigned int Forwarding = 0;
	struct hostent *hent;
	struct sourceinfo source;

	set_internal_sinfo(&source);

	/*
	 *  Close all open log files and free log descriptor array.
	 */
	if (verbose)
		warnx("called init.");

	if (files) {
		if (verbose)
			warnx("initializing log structures.");
		free_files();
	}

	/* Get hostname */
	gethostname(LocalHostName, sizeof(LocalHostName));
	LocalDomain = emptystring;
	if ((p = strchr(LocalHostName, '.'))) {
		*p++        = '\0';
		LocalDomain = p;
	} else if ((options & OPT_ACCEPT_REMOTE)) {
		/*
		 * It's not clearly defined whether gethostname()
		 * should return the simple hostname or the fqdn. A
		 * good piece of software should be aware of both and
		 * we want to distribute good software.  Joey
		 *
		 * Good software also always checks its return values...
		 * If syslogd starts up before DNS is up & /etc/hosts
		 * doesn't have LocalHostName listed, gethostbyname will
		 * return NULL.
		 */
		hent = gethostbyname(LocalHostName);
		if (hent)
			snprintf(LocalHostName, sizeof(LocalHostName), "%s", hent->h_name);

		if ((p = strchr(LocalHostName, '.'))) {
			*p++        = '\0';
			LocalDomain = p;
		}
	}

	/*
	 * Convert to lower case to recognize the correct domain laterly
	 */
	for (p = (char *) LocalDomain; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);

	if (parse_config_file(ConfFile) < 0) {
		if (!(f = allocate_log()))
			return;

		parse_config_line("*.err\t" _PATH_CONSOLE, f);
		return;
	}

	if (epoll_fd < 0 &&
	    (epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
		logerror("epoll_create1: %m");
		exit(1);
	}

	if (signal_fd < 0) {
		signal_fd = signalfd(-1, &signal_mask, SFD_NONBLOCK | SFD_CLOEXEC);
		if (signal_fd < 0) {
			logerror("signalfd: %m");
			exit(1);
		}
		set_input(INPUT_SIGNALFD, NULL, signal_fd);
	}

#ifdef SYSLOG_UNIXAF
	for (struct input *in = inputs; in; in = in->next) {
		if (in->type != INPUT_UNIX)
			continue;
		if (in->fd != -1) {
			/*
			 * Don't close the socket, preserve it instead
			 * close(p->fd);
			 */
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, in->fd, NULL);
			continue;
		}
		if ((in->fd = create_unix_socket(in->name, UNIXAF_BIND)) < 0)
			continue;
		if (verbose)
			warnx("opened UNIX socket `%s' (fd=%d).", in->name, in->fd);
	}
#endif

#ifdef SYSLOG_INET
	for (f = files; f; f = f->next) {
		if (f->f_type == F_FORW || f->f_type == F_FORW_SUSP || f->f_type == F_FORW_UNKN)
			Forwarding++;
	}
	if (Forwarding || (options & OPT_ACCEPT_REMOTE)) {
		if (!InetInuse && create_inet_sockets() > 0) {
			InetInuse = 1;
			if (verbose)
				warnx("opened syslog UDP port.");
		}
	} else {
		for (struct input *in = inputs; in; in = in->next) {
			if (in->type != INPUT_INET || in->fd == -1)
				continue;
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, in->fd, NULL);
			close(in->fd);
			in->fd = -1;
		}
		InetInuse = 0;
	}
#endif
	for (struct input *in = inputs; in; in = in->next) {
		if (in->fd == -1)
			continue;

		struct epoll_event ev = {
			.events   = EPOLLIN,
			.data.ptr = in,
		};

		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, in->fd, &ev) < 0) {
			logerror("epoll_ctl: %m");
			continue;
		}

		if (verbose)
			warnx("listening active file descriptor #%d (%s)", in->fd,
					print_code_name(in->type, InputTypeNames));
	}

	if (verbose > 1) {
		for (f = files; f; f = f->next) {
			if (f->f_type != F_UNUSED) {
				printf("%2d: ", lognum);

				for (i = 0; i <= LOG_NFACILITIES; i++)
					if (f->f_pmask[i] == TABLE_NOPRI)
						printf(" X ");
					else
						printf("%2X ", f->f_pmask[i]);
				printf("%s: ", TypeNames[f->f_type]);
				switch (f->f_type) {
					case F_FILE:
					case F_PIPE:
					case F_TTY:
					case F_CONSOLE:
					case F_UNIXAF:
						printf("%s", f->f_un.f_fname);
						if (f->f_file == -1)
							printf(" (unused)");
						break;

					case F_FORW:
					case F_FORW_SUSP:
					case F_FORW_UNKN:
						printf("%s", f->f_un.f_forw.f_hname);
						break;

					case F_USERS:
						for (i = 0; i < MAXUNAMES && *f->f_un.f_uname[i]; i++)
							printf("%s, ", f->f_un.f_uname[i]);
						break;
					case F_WALL:
						printf("(everyone logged on)");
						break;
					case F_UNUSED:
						break;
				}
				printf("\n");
			}
		}
	}

	if ((options & OPT_ACCEPT_REMOTE))
		logmsg(LOG_SYSLOG | LOG_INFO, "syslogd " VERSION ": restart (remote reception).", &source, 0);
	else
		logmsg(LOG_SYSLOG | LOG_INFO, "syslogd " VERSION ": restart.", &source, 0);

	if (verbose)
		warnx("restarted.");
}

void set_pmask(int i, int pri, int flags, struct filed *f)
{
	if (pri == INTERNAL_NOPRI) {
		f->f_pmask[i] = (flags & PMASK_FLAG_IGNOREPRI)
		                    ? TABLE_ALLPRI
		                    : TABLE_NOPRI;
	} else if (flags & PMASK_FLAG_SINGLEPRI) {
		if (flags & PMASK_FLAG_IGNOREPRI)
			f->f_pmask[i] &= ~(1 << pri);
		else
			f->f_pmask[i] |= (1 << pri);
	} else if (pri == TABLE_ALLPRI) {
		f->f_pmask[i] = (flags & PMASK_FLAG_IGNOREPRI)
		                    ? TABLE_NOPRI
		                    : TABLE_ALLPRI;
	} else {
		for (int i2 = 0; i2 <= pri; ++i2)
			if (flags & PMASK_FLAG_IGNOREPRI)
				f->f_pmask[i] &= ~(1 << i2);
			else
				f->f_pmask[i] |= (1 << i2);
	}
}

/*
 * Crack a configuration file line
 */
void parse_config_line(const char *line, struct filed *f)
{
	register const char *p;
	register const char *q;
	register int i;
	char *bp, *ptr;
	int pri;
	int syncfile;
#ifdef SYSLOG_INET
	struct addrinfo hints, *ai;
#endif
	char buf[MAXLINE];

	if (verbose)
		warnx("parse_config_line(%s)", line);

	errno = 0; /* keep strerror() stuff out of logerror messages */

	for (i = 0; i <= LOG_NFACILITIES; i++) {
		f->f_pmask[i] = TABLE_NOPRI;
		f->f_flags    = 0;
	}

	/* scan through the list of selectors */
	for (p = line; *p && *p != '\t' && *p != ' ';) {
		int flags = 0;

		/* find the end of this facility name list */
		for (q = p; *q && *q != '\t' && *q++ != '.';)
			continue;

		/* collect priority name */
		for (bp = buf; *q && !strchr("\t ,;", *q);)
			*bp++ = *q++;
		*bp = '\0';

		/* skip cruft */
		while (strchr(",;", *q))
			q++;

		/* decode priority name */
		if (*buf == '!') {
			flags |= PMASK_FLAG_IGNOREPRI;
			for (bp = buf; *(bp + 1); bp++)
				*bp = *(bp + 1);
			*bp = '\0';
		}
		if (*buf == '=') {
			flags |= PMASK_FLAG_SINGLEPRI;
			ptr = buf + 1;
		} else {
			ptr = buf;
		}

		if (*ptr == '*') {
			pri = TABLE_ALLPRI;
			if (verbose)
				warnx("symbolic name: %s ==> %d", ptr, pri);
		} else {
			pri = decode(ptr, bb_prioritynames);
		}

		if (pri < 0) {
			logerror("unknown priority name \"%s\"", buf);
			return;
		}

		/* scan facilities */
		while (*p && !strchr("\t .;", *p)) {
			for (bp = buf; *p && !strchr("\t ,;.", *p);)
				*bp++ = *p++;
			*bp = '\0';
			if (*buf == '*') {
				for (i = 0; i <= LOG_NFACILITIES; i++)
					set_pmask(i, pri, flags, f);
			} else {
				if ((i = decode(buf, bb_facilitynames)) < 0) {
					logerror("unknown facility name \"%s\"", buf);
					return;
				}
				set_pmask(i >> 3, pri, flags, f);
			}
			while (*p == ',' || *p == ' ')
				p++;
		}

		p = q;
	}

	/* skip to action part */
	while (*p == '\t' || *p == ' ')
		p++;

	if (*p == '-') {
		syncfile = 0;
		p++;
	} else
		syncfile = 1;

	if (verbose)
		warnx("leading char in action: %c", *p);

	switch (*p) {
		case '@':
			q = ++p;
#ifdef SYSLOG_UNIXAF
			if (*q == '/') {
				safe_strncpy(f->f_un.f_fname, q, sizeof(f->f_un.f_fname));

				if (verbose)
					warnx("forwarding unix domain socket: %s", p); /*ASP*/

				f->f_type = F_UNIXAF;
				f->f_file = create_unix_socket(q, UNIXAF_CONNECT);

				if (f->f_file < 0) {
					f->f_file = -1;
					break;
				}

				set_nonblock_flag(f->f_file);
				break;
			}
#endif
#ifdef SYSLOG_INET
			safe_strncpy(f->f_un.f_forw.f_hname, q, sizeof(f->f_un.f_forw.f_hname));

			if (verbose)
				warnx("forwarding host: %s", p); /*ASP*/

			memset(&hints, 0, sizeof(hints));
			hints.ai_family   = family;
			hints.ai_socktype = SOCK_DGRAM;
			if (getaddrinfo(p, "syslog", &hints, &ai)) {
				/*
				 * The host might be unknown due to an
				 * inaccessible nameserver (perhaps on the
				 * same host). We try to get the ip number
				 * later, like FORW_SUSP.
				 */
				f->f_type             = F_FORW_UNKN;
				f->f_prevcount        = INET_RETRY_MAX;
				f->f_time             = time((time_t *) 0);
				f->f_un.f_forw.f_addr = NULL;
			} else {
				f->f_type             = F_FORW;
				f->f_un.f_forw.f_addr = ai;
			}
#endif
			break;

		case '|':
		case '/':
			safe_strncpy(f->f_un.f_fname, p, sizeof(f->f_un.f_fname));

			if (verbose)
				warnx("filename: %s", p); /*ASP*/

			if (syncfile)
				f->f_flags |= SYNC_FILE;
			if (*p == '|') {
				f->f_file = open(++p, O_RDWR | O_NONBLOCK | O_NOCTTY);
				f->f_type = F_PIPE;
			} else {
				f->f_file = open(p, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_NOCTTY,
				                 0600);
				f->f_type = F_FILE;
			}

			if (f->f_file < 0) {
				f->f_file = -1;
				logerror("Error opening log file: %s: %m", p);
				break;
			}
			if (isatty(f->f_file)) {
				set_nonblock_flag(f->f_file);
				f->f_type = F_TTY;
				untty();
			}
			if (!strcmp(p, consfile.f_un.f_fname))
				f->f_type = F_CONSOLE;
			break;

		case '*':
			if (verbose)
				warnx("write-all");
			f->f_type = F_WALL;
			break;

		default:
			if (verbose)
				warnx("users: %s", p); /* ASP */
			for (i = 0; i < MAXUNAMES && *p; i++) {
				for (q = p; *q && *q != ',';)
					q++;
				safe_strncpy(f->f_un.f_uname[i], p, UNAMESZ);
				if ((q - p) > UNAMESZ)
					f->f_un.f_uname[i][UNAMESZ] = '\0';
				else
					f->f_un.f_uname[i][q - p] = '\0';
				while (*q == ',' || *q == ' ')
					q++;
				p = q;
			}
			f->f_type = F_USERS;
			break;
	}
	return;
}

int parse_config_file(const char *filename)
{
	FILE *fd;
	int rc = -1;
	char cbuf[BUFSIZ];
	char *cline;

	if (verbose)
		warnx("parse_config_file(%s)", filename);

	if (!(fd = fopen(filename, "r"))) {
		logerror("cannot open %s", filename);
		return rc;
	}

	/*
	 *  Foreach line in the conf table, open that file.
	 */
	cline = cbuf;
	while (fgets(cline, sizeof(cbuf) - (cline - cbuf), fd)) {
		struct filed *f;
		char *p;

		/*
		 * check for end-of-section, comments, strip off trailing
		 * spaces and newline character.
		 */
		for (p = cline; isspace(*p); ++p)
			;
		if (*p == '\0' || *p == '#')
			continue;

		memmove(cline, p, strlen(p) + 1);

		for (p = strchr(cline, '\0'); isspace(*--p);)
			;

		if (*p == '\\') {
			if ((p - cbuf) > BUFSIZ - 30) {
				/* Oops the buffer is full - what now? */
				cline = cbuf;
			} else {
				*p    = 0;
				cline = p;
				continue;
			}
		} else
			cline = cbuf;

		*++p = '\0';

		if (!strncmp("log_format:", cbuf, 11)) {
			for (p = cbuf + 11; isspace(*p); ++p)
				;
			parse_log_format(&log_fmt, p);
			continue;
		}

		if (!(f = allocate_log()))
			goto err;

		parse_config_line(cbuf, f);
	}

	rc = 0;
err:
	fclose(fd);
	return rc;
}

/*
 *  Decode a symbolic name to a numeric value
 */
int decode(const char *name, const CODE *c)
{
	if (isdigit(*name)) {
		int val = atoi(name);

		for (; c->c_name; c++)
			if (val == c->c_val) {
				if (verbose)
					warnx("symbolic name: %s", name);
				return val;
			}
	} else {
		for (; c->c_name; c++)
			if (!strcasecmp(name, c->c_name)) {
				if (verbose)
					warnx("symbolic name: %s ==> %d", name, c->c_val);
				return c->c_val;
			}
	}
	if (verbose)
		warnx("symbolic name: %s => not found", name);
	return -1;
}

const char *print_code_name(int val, const CODE *c)
{
	for (; c->c_name; c++) {
		if (c->c_val == val)
			return c->c_name;
	}
	return "";
}

/*
 * The following function is responsible for allocating/reallocating the
 * array which holds the structures which define the logging outputs.
 */
struct filed *allocate_log(void)
{
	struct filed *new;

	if (verbose)
		warnx("allocating new log structure.");

	new = calloc(1, sizeof(*new));
	if (!new) {
		logerror("cannot initialize log structure.");
		return NULL;
	}

	safe_strncpy(new->f_prevhash, EMPTY_HASH_LITERAL, sizeof(new->f_prevhash));

	new->next = files;
	files     = new;

	return files;
}

int set_log_format_field(struct log_format *fmt, size_t i,
                         enum log_format_type t, const char *s, size_t n)
{
	if (i >= iovec_max) {
		logerror("Too many parts in the log_format string");
		return -1;
	}

	if (t != LOG_FORMAT_NONE) {
		if (fmt->fields_nr >= LOG_FORMAT_FIELDS_MAX) {
			logerror("Too many placeholders in the log_format string");
			return -1;
		}

		fmt->f_mask |= (1U << t);
		fmt->fields[fmt->fields_nr].f_type = t;
		fmt->fields[fmt->fields_nr].f_iov  = fmt->iov + i;
		fmt->fields_nr++;
	}

	fmt->iov[i].iov_base = (void *) s;
	fmt->iov[i].iov_len  = n;
	fmt->iovec_nr++;

	return 0;
}

int parse_log_format(struct log_format *fmt, const char *str)
{
	const char *ptr, *start;
	int i, special;
	size_t field_nr;
	struct log_format new_fmt = { 0 };

	iovec_max = sysconf(_SC_IOV_MAX);

	new_fmt.line = calloc(1, LINE_MAX);
	if (!new_fmt.line) {
		logerror("Cannot allocate log_format string");
		goto error;
	}

	new_fmt.iov = calloc(LOG_FORMAT_IOVEC_MAX, sizeof(struct iovec));
	if (!new_fmt.iov) {
		logerror("Cannot allocate records array for log_format string");
		goto error;
	}

	new_fmt.fields = calloc(LOG_FORMAT_FIELDS_MAX, sizeof(struct log_format_field));
	if (!new_fmt.fields) {
		logerror("Cannot allocate rules array for log_format string");
		goto error;
	}

	ptr = str;
	i = special = 0;

	while (*ptr != '\0' && i < LINE_MAX) {
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

	field_nr = 0;
	special  = 0;
	i        = 0;

	if (set_log_format_field(&new_fmt, field_nr++, LOG_FORMAT_BOL, NULL, 0) < 0)
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
				case 'H':
					f_type = LOG_FORMAT_HASH;
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
		    set_log_format_field(&new_fmt, field_nr++,
		                         LOG_FORMAT_NONE, start, (size_t)(ptr - start - 1)) < 0)
			goto error;

		if (set_log_format_field(&new_fmt, field_nr++, f_type, NULL, 0) < 0)
			goto error;

		start = ptr + 1;
		goto next;
	create_special:
		if (set_log_format_field(&new_fmt, field_nr++,
		                         LOG_FORMAT_NONE, start, (size_t)(ptr - start - 1)) < 0)
			goto error;

		start = ptr;
		goto next;
	}

	if (special) {
		logerror("unexpected '%%' at the end of line");
		goto error;
	}

	if (start != ptr &&
	    set_log_format_field(&new_fmt, field_nr++,
	                         LOG_FORMAT_NONE, start, (size_t)(ptr - start)) < 0)
		goto error;

	if (set_log_format_field(&new_fmt, field_nr++,
	                         LOG_FORMAT_EOL, NULL, 0) < 0)
		goto error;

	free(fmt->line);
	free(fmt->iov);
	free(fmt->fields);

	fmt->line   = new_fmt.line;
	fmt->iov    = new_fmt.iov;
	fmt->fields = new_fmt.fields;

	return 0;
error:
	free_log_format(&new_fmt);

	return -1;
}

void free_log_format(struct log_format *fmt)
{
	free(fmt->line);
	free(fmt->iov);
	free(fmt->fields);
}

void free_inputs(void)
{
	struct input *inp = inputs;

	while (inp) {
		struct input *inp_next = inp->next;
		if (inp->fd >= 0) {
			if (inp->type == INPUT_UNIX)
				unlink(inp->name);
			close(inp->fd);
		}
		free(inp);
		inp = inp_next;
	}
}

void free_files(void)
{
	struct filed *f, *next;
	struct sourceinfo source;

	set_internal_sinfo(&source);

	f = files;
	while (f) {
		/* flush any pending output */
		if (f->f_prevcount)
			fprintlog(f, &source, 0, NULL);

		switch (f->f_type) {
			case F_FILE:
			case F_PIPE:
			case F_TTY:
			case F_CONSOLE:
			case F_UNIXAF:
				close(f->f_file);
				break;
			case F_FORW:
			case F_FORW_SUSP:
				freeaddrinfo(f->f_un.f_forw.f_addr);
				break;
			default:
				break;
		}

		next = f->next;
		free(f);
		f = next;
	}

	/*
	 * This is needed especially when HUPing syslogd as the
	 * structure would grow infinitively.  -Joey
	 */
	files = NULL;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
