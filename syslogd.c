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

#define SYSLOG_NAMES
#include <sys/syslog.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>
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
#include "version.h"
#include "attribute.h"
#include "hash.h"

#if defined(__linux__)
#include <paths.h>
#endif

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

#if defined(SYSLOGD_PIDNAME)
#undef _PATH_LOGPID
#if defined(FSSTND)
#define _PATH_LOGPID _PATH_VARRUN SYSLOGD_PIDNAME
#else
#define _PATH_LOGPID "/etc/" SYSLOGD_PIDNAME
#endif
#else
#ifndef _PATH_LOGPID
#if defined(FSSTND)
#define _PATH_LOGPID _PATH_VARRUN "syslogd.pid"
#else
#define _PATH_LOGPID "/etc/syslogd.pid"
#endif
#endif
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
static const char ctty[]    = _PATH_CONSOLE;

static char **parts;

static int debugging_on = 0;
static int nlogs        = -1;
static int restart      = 0;

#define MAXFUNIX 20

static int nfunix                   = 1;
static const char *funixn[MAXFUNIX] = { _PATH_LOG };
static int funix[MAXFUNIX]          = {
        -1,
};

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
#define ADDDATE   0x004 /* add a date to the message */
#define MARK      0x008 /* this message is a mark */

/*
 * This structure represents the files that will have log
 * copies printed.
 */

struct filed {
	short f_type;                        /* entry type, see below */
	short f_file;                        /* file descriptor */
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
	char f_lasttime[16];                 /* time of last occurrence */
	char f_prevhost[MAXHOSTNAMELEN + 1]; /* host from which recd. */
	int f_prevpri;                       /* pri of f_prevline */
	int f_prevlen;                       /* length of f_prevline */
	int f_prevcount;                     /* repetition cnt of prevline */
	int f_repeatcount;                   /* number of "repeated" msgs */
	int f_flags;                         /* store some additional flags */
	/* hash of last logged message */
	char f_prevhash[HASH_NAMESZ + 1 + HASH_HEXSZ + 1];
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

/* values for f_type */
#define F_UNUSED    0 /* unused entry */
#define F_FILE      1 /* regular file */
#define F_TTY       2 /* terminal */
#define F_CONSOLE   3 /* console terminal */
#define F_FORW      4 /* remote machine */
#define F_USERS     5 /* list of users */
#define F_WALL      6 /* everyone logged on */
#define F_FORW_SUSP 7 /* suspended host forwarding */
#define F_FORW_UNKN 8 /* unknown host forwarding */
#define F_PIPE      9 /* named pipe */
static const char *TypeNames[] = {
	"UNUSED", "FILE", "TTY", "CONSOLE",
	"FORW", "USERS", "WALL", "FORW(SUSPENDED)",
	"FORW(UNKNOWN)", "PIPE"
};

static struct filed *Files = (struct filed *) 0;
static struct filed consfile;

struct code {
	const char *c_name;
	int c_val;
};

static struct code PriNames[] = {
	{ "alert", LOG_ALERT },
	{ "crit", LOG_CRIT },
	{ "debug", LOG_DEBUG },
	{ "emerg", LOG_EMERG },
	{ "err", LOG_ERR },
	{ "error", LOG_ERR }, /* DEPRECATED */
	{ "info", LOG_INFO },
	{ "none", INTERNAL_NOPRI }, /* INTERNAL */
	{ "notice", LOG_NOTICE },
	{ "panic", LOG_EMERG },  /* DEPRECATED */
	{ "warn", LOG_WARNING }, /* DEPRECATED */
	{ "warning", LOG_WARNING },
	{ "*", TABLE_ALLPRI },
	{ NULL, -1 }
};

static struct code FacNames[] = {
	{ "auth", LOG_AUTH },
	{ "authpriv", LOG_AUTHPRIV },
	{ "cron", LOG_CRON },
	{ "daemon", LOG_DAEMON },
	{ "kern", LOG_KERN },
	{ "lpr", LOG_LPR },
	{ "mail", LOG_MAIL },
	{ "mark", LOG_MARK }, /* INTERNAL */
	{ "news", LOG_NEWS },
	{ "security", LOG_AUTH }, /* DEPRECATED */
	{ "syslog", LOG_SYSLOG },
	{ "user", LOG_USER },
	{ "uucp", LOG_UUCP },
#if defined(LOG_FTP)
	{ "ftp", LOG_FTP },
#endif
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
	{ NULL, -1 },
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
} sinfo;

enum log_format_type {
	LOG_FORMAT_NONE = 0,
	LOG_FORMAT_BOL,
	LOG_FORMAT_HASH,
	LOG_FORMAT_TIME,
	LOG_FORMAT_HOST,
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
};

static struct log_format log_fmt = { 0 };
static long int iovec_max        = 0;

static int Debug;                              /* debug flag */
static int Compress = 1;                       /* compress repeated messages flag */
static char LocalHostName[MAXHOSTNAMELEN + 1]; /* our hostname */
static const char *LocalDomain;                /* our local domain name */
static const char *emptystring  = "";
static int InetInuse            = 0;       /* non-zero if INET sockets are being used */
static int *finet               = NULL;    /* Internet datagram sockets */
static int Initialized          = 0;       /* set when we have initialized ourselves */
static int LogFormatInitialized = 0;       /* set when we have initialized log_format */
static int MarkInterval         = 20 * 60; /* interval between marks in seconds */
#ifdef INET6
static int family = PF_UNSPEC; /* protocol family (IPv4, IPv6 or both) */
#else
static int family = PF_INET; /* protocol family (IPv4 only) */
#endif
static int send_to_all     = 0;    /* send message to all IPv4/IPv6 addresses */
static int MarkSeq         = 0;    /* mark sequence number */
static int LastAlarm       = 0;    /* last value passed to alarm() (seconds)  */
static int DupesPending    = 0;    /* Number of unflushed duplicate messages */
static int NoFork          = 0;    /* don't fork - don't run in daemon mode */
static int AcceptRemote    = 0;    /* receive messages that come via UDP */
static char **StripDomains = NULL; /* these domains may be stripped before writing logs */
static char **LocalHosts   = NULL; /* these hosts are logged with their hostname */
static int NoHops          = 1;    /* Can we bounce syslog messages through an
					   intermediate host. */

static char *bind_addr   = NULL; /* bind UDP port to this interface only */
static char *server_user = NULL; /* user name to run server as */
static char *chroot_dir  = NULL; /* user name to run server as */

#ifndef errno
extern int errno;
#endif

/* Function prototypes. */
int main(int argc, char **argv);
char **crunch_list(char *list);
int usage(void);
void untty(void);
void printchopped(const struct sourceinfo *const, char *msg, size_t len, int fd);
void printline(const struct sourceinfo *const, char *msg);
void logmsg(int pri, const char *msg, const struct sourceinfo *const, int flags);
char *get_record_field(struct log_format *log_fmt, enum log_format_type name)
    SYSKLOGD_NONNULL((1));
void clear_record_fields(struct log_format *log_fmt)
    SYSKLOGD_NONNULL((1));
void set_record_field(struct log_format *log_fmt, enum log_format_type name,
		const char *value, ssize_t len)
    SYSKLOGD_NONNULL((1));
void fprintlog(register struct filed *f, char *from, int flags, const char *msg);
void endtty(int);
void wallmsg(register struct filed *f, struct log_format *log_fmt);
void reapchild(int);
const char *cvtaddr(struct sockaddr_storage *f, int len);
const char *cvthname(struct sockaddr_storage *f, int len);
void domark(int);
void debug_switch(int);
void logerror(const char *fmt, ...)
    SYSKLOGD_FORMAT((__printf__, 1, 2)) SYSKLOGD_NONNULL((1));
void die(int sig);
void doexit(int sig);
void init(void);
void cfline(const char *line, register struct filed *f);
int decode(char *name, struct code *codetab);
void verbosef(const char *, ...)
    SYSKLOGD_FORMAT((__printf__, 1, 2)) SYSKLOGD_NONNULL((1));
void allocate_log(void);
int set_log_format_field(struct log_format *log_fmt, size_t i, enum log_format_type t,
		const char *s, size_t n)
    SYSKLOGD_NONNULL((1));
int parse_log_format(struct log_format *log_fmt, const char *s);
void calculate_digest(struct filed *f, struct log_format *log_fmt);
void sighup_handler(int);
int set_nonblock_flag(int desc);
int create_unix_socket(const char *path) SYSKLOGD_NONNULL((1));
ssize_t recv_withcred(int s, void *buf, size_t len, int flags, pid_t *pid, uid_t *uid, gid_t *gid);
int *create_inet_sockets(void);
int drop_root(void);
void add_funix_name(const char *fname) SYSKLOGD_NONNULL((1));
void add_funix_dir(const char *dname) SYSKLOGD_NONNULL((1));
char *textpri(int pri);

#ifdef SYSLOG_UNIXAF
int create_unix_socket(const char *path)
{
	struct sockaddr_un sunx;
	int fd;
	char line[MAXLINE + 1];
	int passcred = 1;
	socklen_t sl = sizeof(passcred);

	if (path[0] == '\0')
		return -1;

	(void) unlink(path);

	memset(&sunx, 0, sizeof(sunx));
	sunx.sun_family = AF_UNIX;
	(void) strncpy(sunx.sun_path, path, sizeof(sunx.sun_path) - 1);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0 ||
	    bind(fd, (struct sockaddr *) &sunx, sizeof(sunx.sun_family) + strlen(sunx.sun_path)) < 0 ||
	    chmod(path, 0666) < 0) {
		(void) snprintf(line, sizeof(line), "cannot create %s", path);
		logerror(line);
		verbosef("cannot create %s (%d).\n", path, errno);
		close(fd);
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred, sl);
	return fd;
}

ssize_t recv_withcred(int s, void *buf, size_t len, int flags,
                      pid_t *pid, uid_t *uid, gid_t *gid)
{
	struct cmsghdr *cmptr;
	struct msghdr m;
	struct iovec iov;
	char control[CMSG_SPACE(sizeof(struct ucred))];
	size_t rc;

	memset(&m, 0, sizeof(m));
	memset(control, 0, sizeof(control));

	iov.iov_base = (char *) buf;
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
int *create_inet_sockets(void)
{
	struct addrinfo hints, *res, *r;
	int error, maxs, *s, *socks;
	int on = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_family   = family;
	hints.ai_socktype = SOCK_DGRAM;

	error = getaddrinfo(bind_addr, "syslog", &hints, &res);
	if (error) {
		logerror("network logging disabled (syslog/udp service unknown or address incompatible).");
		logerror("see syslogd(8) for details of whether and how to enable it.");
		logerror(gai_strerror(error));
		return NULL;
	}

	/* Count max number of sockets we may open */
	for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
		;
	socks = malloc((maxs + 1) * sizeof(int));
	if (!socks) {
		logerror("couldn't allocate memory for sockets");
		die(0);
	}

	*socks = 0; /* num of sockets counter at start of array */
	s      = socks + 1;
	for (r = res; r; r = r->ai_next) {
		*s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (*s < 0) {
			logerror("socket");
			continue;
		}
		if (r->ai_family == AF_INET6) {
			if (setsockopt(*s, IPPROTO_IPV6, IPV6_V6ONLY,
			               (char *) &on, sizeof(on)) < 0) {
				logerror("setsockopt (IPV6_ONLY), suspending IPv6");
				close(*s);
				continue;
			}
		}
		if (setsockopt(*s, SOL_SOCKET, SO_REUSEADDR,
		               (char *) &on, sizeof(on)) < 0) {
			logerror("setsockopt(REUSEADDR), suspending inet");
			close(*s);
			continue;
		}
		/*
		 * We must not block on the network socket, in case a packet
		 * gets lost between select and recv, otherise the process
		 * will stall until the timeout, and other processes trying to
		 * log will also stall.
		 */
		if (set_nonblock_flag(*s) == -1) {
			logerror("fcntl(O_NONBLOCK), suspending inet");
			close(*s);
			continue;
		}
		if (bind(*s, r->ai_addr, r->ai_addrlen) < 0) {
			logerror("bind, suspending inet");
			close(*s);
			continue;
		}
		(*socks)++;
		s++;
	}
	if (res)
		freeaddrinfo(res);
	if (*socks == 0) {
		logerror("no valid sockets, suspending inet");
		free(socks);
		return NULL;
	}
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

void add_funix_name(const char *fname)
{
	unsigned i;

	for (i = 0; i < MAXFUNIX; ++i)
		if (!strcmp(fname, funixn[i]))
			return;

	if (nfunix < MAXFUNIX)
		funixn[nfunix++] = fname;
	else
		fprintf(stderr, "Out of descriptors, ignoring %s\n", fname);
}

void add_funix_dir(const char *dname)
{
	DIR *dir;
	struct dirent *entry;

	if (chdir(dname)) {
		fprintf(stderr, "chdir: %s: %s\n", dname, strerror(errno));
		return;
	}

	if (!(dir = opendir("."))) {
		fprintf(stderr, "opendir: %s: %s\n", dname, strerror(errno));
		exit(1);
		return;
	}

	while ((entry = readdir(dir))) {
		struct stat st;

		if (strchr(entry->d_name, '.'))
			continue;

		if (lstat(entry->d_name, &st))
			continue;

		if (S_ISLNK(st.st_mode)) {
			const char *name;
			char buf[MAXPATHLEN];
			int n = readlink(entry->d_name, buf, sizeof(buf));

			if ((n <= 0) || (n >= sizeof(buf)) || (buf[0] != '/'))
				continue;
			buf[n] = '\0';

			if ((name = strdup(buf)) == NULL) {
				printf("Sorry, can't get enough memory, exiting.\n");
				exit(1);
			}
			add_funix_name(name);
		}
	}

	if (closedir(dir))
		fprintf(stderr, "closedir: %s: %s\n", dname, strerror(errno));
	if (chdir("/") < 0) {
		fprintf(stderr, "syslogd: chdir to / failed: %m");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	register int i;
	ssize_t msglen;
	socklen_t len;
	int num_fds;
	/*
	 * It took me quite some time to figure out how this is
	 * supposed to work so I guess I should better write it down.
	 * unixm is a list of file descriptors from which one can
	 * read().  This is in contrary to readfds which is a list of
	 * file descriptors where activity is monitored by select()
	 * and from which one cannot read().  -Joey
	 *
	 * Changed: unixm is gone, since we now use datagram unix sockets.
	 * Hence we recv() from unix sockets directly (rather than
	 * first accept()ing connections on them), so there's no need
	 * for separate book-keeping.  --okir
	 */
	fd_set readfds;

	int fd;
#ifdef SYSLOG_INET
	struct sockaddr_storage frominet;
#endif
	pid_t ppid = getpid();
	int ch;

	char line[MAXLINE + 1];
	extern int optind;
	extern char *optarg;
	int maxfds;
	const char *funix_dir = "/etc/syslog.d";

	if (chdir("/") < 0) {
		fprintf(stderr, "syslogd: chdir to / failed: %m");
		exit(1);
	}

	for (i = 1; i < MAXFUNIX; i++) {
		funixn[i] = "";
		funix[i]  = -1;
	}

	while ((ch = getopt(argc, argv, "46Aa:cdhf:i:j:l:m:np:P:rs:u:v")) != EOF)
		switch ((char) ch) {
			case '4':
				family = PF_INET;
				break;
#ifdef INET6
			case '6':
				family = PF_INET6;
				break;
#endif
			case 'A':
				send_to_all++;
				break;
			case 'a':
				add_funix_name(optarg);
				break;
			case 'c': /* don't compress repeated messages */
				Compress = 0;
				break;
			case 'd': /* debug */
				Debug = 1;
				break;
			case 'f': /* configuration file */
				ConfFile = optarg;
				break;
			case 'h':
				NoHops = 0;
				break;
			case 'i':
				if (bind_addr) {
					fprintf(stderr, "Only one -i argument allowed, "
					                "the first one is taken.\n");
					break;
				}
				bind_addr = optarg;
				break;
			case 'j':
				chroot_dir = optarg;
				break;
			case 'l':
				if (LocalHosts) {
					fprintf(stderr, "Only one -l argument allowed, "
					                "the first one is taken.\n");
					break;
				}
				LocalHosts = crunch_list(optarg);
				break;
			case 'm': /* mark interval */
				MarkInterval = atoi(optarg) * 60;
				break;
			case 'n': /* don't fork */
				NoFork = 1;
				break;
			case 'p': /* path to regular log socket */
				funixn[0] = optarg;
				break;
			case 'P':
				funix_dir = optarg;
				break;
			case 'r': /* accept remote messages */
				AcceptRemote = 1;
				break;
			case 's':
				if (StripDomains) {
					fprintf(stderr, "Only one -s argument allowed,"
					                "the first one is taken.\n");
					break;
				}
				StripDomains = crunch_list(optarg);
				break;
			case 'u':
				server_user = optarg;
				break;
			case 'v':
				printf("syslogd %s.%s\n", VERSION, PATCHLEVEL);
				exit(0);
			case '?':
			default:
				usage();
		}
	if ((argc -= optind))
		usage();

	if (chroot_dir && !server_user) {
		fputs("'-j' is only valid with '-u'\n", stderr);
		exit(1);
	}
	if (funix_dir && *funix_dir)
		add_funix_dir(funix_dir);

	if (parse_log_format(&log_fmt, "%t %h %m") < 0)
		exit(1);

	if (!(Debug || NoFork)) {
		verbosef("Checking pidfile.\n");
		if (!check_pid(PidFile)) {
			pid_t pid;

			if ((fd = open(_PATH_DEVNULL, O_RDWR)) < 0) {
				fprintf(stderr, "syslogd: %s: %s\n",
				        _PATH_DEVNULL, strerror(errno));
				exit(1);
			}

			signal(SIGTERM, doexit);
			if ((pid = fork()) == -1) {
				fputs("syslogd: fork failed.\n", stderr);
				exit(1);
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
			if (dup2(fd, 0) != 0 || dup2(fd, 1) != 1 || dup2(fd, 2) != 2) {
				fputs("syslogd: dup2 failed.\n", stderr);
				exit(1);
			}
			for (i = 3; i < num_fds; i++)
				(void) close(i);
			untty();
		} else {
			fputs("syslogd: Already running.\n", stderr);
			exit(1);
		}
	} else
		debugging_on = 1;

	/* tuck my process id away */
	if (!Debug) {
		verbosef("Writing pidfile.\n");
		if (!check_pid(PidFile)) {
			if (!write_pid(PidFile)) {
				verbosef("Can't write pid.\n");
				if (getpid() != ppid)
					kill(ppid, SIGTERM);
				exit(1);
			}
		} else {
			verbosef("Pidfile (and pid) already exist.\n");
			if (getpid() != ppid)
				kill(ppid, SIGTERM);
			exit(1);
		}
	} /* if ( !Debug ) */

	consfile.f_type = F_CONSOLE;
	(void) strcpy(consfile.f_un.f_fname, ctty);

	/* Initialization is done by init() */
	(void) strcpy(LocalHostName, emptystring);
	LocalDomain = emptystring;

	(void) signal(SIGTERM, die);
	(void) signal(SIGINT, Debug ? die : SIG_IGN);
	(void) signal(SIGQUIT, Debug ? die : SIG_IGN);
	(void) signal(SIGCHLD, reapchild);
	(void) signal(SIGALRM, domark);
	(void) signal(SIGUSR1, Debug ? debug_switch : SIG_IGN);
	(void) signal(SIGXFSZ, SIG_IGN);

	LastAlarm = MarkInterval;
	alarm(LastAlarm);

	/* Create a partial message table for all file descriptors. */
	num_fds = getdtablesize();
	verbosef("Allocated parts table for %d file descriptors.\n", num_fds);
	if ((parts = (char **) malloc(num_fds * sizeof(char *))) ==
	    (char **) 0) {
		logerror("Cannot allocate memory for message parts table.");

		if (getpid() != ppid)
			kill(ppid, SIGTERM);

		die(0);
	}
	for (i = 0; i < num_fds; ++i)
		parts[i] = (char *) 0;

	verbosef("Starting.\n");
	init();

	if (Debug) {
		verbosef("Debugging disabled, SIGUSR1 to turn on debugging.\n");
		debugging_on = 0;
	}
	/*
	 * Send a signal to the parent to it can terminate.
	 */
	if (getpid() != ppid)
		kill(ppid, SIGTERM);

	if (server_user && drop_root()) {
		verbosef("syslogd: failed to drop root\n");
		exit(1);
	}

	/*
	 * Main loop begins here.
	 */
	for (;;) {
		int nfds;
		errno = 0;
		FD_ZERO(&readfds);
		maxfds = 0;
#ifdef SYSLOG_UNIXAF
		/*
		 * Add the Unix Domain Sockets to the list of read
		 * descriptors.
		 */
		/* Copy master connections */
		for (i = 0; i < nfunix; i++) {
			if (funix[i] != -1) {
				FD_SET(funix[i], &readfds);
				if (funix[i] > maxfds) maxfds = funix[i];
			}
		}
#endif
#ifdef SYSLOG_INET
		/*
		 * Add the Internet Domain Socket to the list of read
		 * descriptors.
		 */
		if (InetInuse && AcceptRemote) {
			for (i = 0; i < *finet; i++) {
				if (finet[i + 1] != -1)
					FD_SET(finet[i + 1], &readfds);
				if (finet[i + 1] > maxfds) maxfds = finet[i + 1];
			}
			verbosef("Listening on syslog UDP port.\n");
		}
#endif

		if (debugging_on) {
			verbosef("Calling select, active file descriptors (max %d): ", maxfds);
			for (nfds = 0; nfds <= maxfds; ++nfds)
				if (FD_ISSET(nfds, &readfds))
					verbosef("%d ", nfds);
			verbosef("\n");
		}
		nfds = select(maxfds + 1, (fd_set *) &readfds, (fd_set *) NULL,
		              (fd_set *) NULL, (struct timeval *) NULL);
		if (restart) {
			restart = 0;
			verbosef("\nReceived SIGHUP, reloading syslogd.\n");
			init();
			continue;
		}
		if (nfds == 0) {
			verbosef("No select activity.\n");
			continue;
		}
		if (nfds < 0) {
			if (errno != EINTR)
				logerror("select");
			verbosef("Select interrupted.\n");
			continue;
		}

		if (debugging_on) {
			verbosef("\nSuccessful select, descriptor count = %d, "
			         "Activity on: ",
			         nfds);
			for (nfds = 0; nfds <= maxfds; ++nfds)
				if (FD_ISSET(nfds, &readfds))
					verbosef("%d ", nfds);
			verbosef(("\n"));
		}

#ifdef SYSLOG_UNIXAF
		for (i = 0; i < nfunix; i++) {
			if ((fd = funix[i]) != -1 && FD_ISSET(fd, &readfds)) {
				memset(&sinfo, '\0', sizeof(sinfo));
				memset(line, 0, sizeof(line));

				msglen = recv_withcred(fd, line, MAXLINE - 2, 0,
				                       &sinfo.pid, &sinfo.uid, &sinfo.gid);

				verbosef("Message from UNIX socket: #%d\n", fd);

				if (sinfo.uid == -1 || sinfo.gid == -1 || sinfo.pid == -1)
					logerror("error - credentials not provided");
				else
					sinfo.flags = SINFO_HAVECRED;

				if (msglen > 0) {
					sinfo.hostname = LocalHostName;
					printchopped(&sinfo, line, msglen + 2, fd);
				} else if (msglen < 0 && errno != EINTR) {
					verbosef("UNIX socket error: %d = %s.\n",
					         errno, strerror(errno));
					logerror("recvfrom UNIX");
				}
			}
		}
#endif

#ifdef SYSLOG_INET
		if (InetInuse && AcceptRemote && finet) {
			for (i = 0; i < *finet; i++) {
				if (finet[i + 1] != -1 && FD_ISSET(finet[i + 1], &readfds)) {
					len = sizeof(frominet);
					memset(line, 0, sizeof(line));
					memset(&sinfo, '\0', sizeof(sinfo));
					msglen = recvfrom(finet[i + 1], line, MAXLINE - 2, 0,
					                  (struct sockaddr *) &frominet, &len);
					if (Debug) {
						const char *addr = cvtaddr(&frominet, len);
						verbosef("Message from inetd socket: #%d, host: %s\n",
						         i + 1, addr);
					}
					if (msglen > 0) {
						/* Note that if cvthname() returns NULL then
						   we shouldn't attempt to log the line -- jch */
						sinfo.hostname = (char *) cvthname(&frominet, len);
						printchopped(&sinfo, line,
						             msglen + 2, finet[i + 1]);
					} else if (msglen < 0 && errno != EINTR && errno != EAGAIN) {
						verbosef("INET socket error: %d = %s.\n",
						         errno, strerror(errno));
						logerror("recvfrom inet");
						/* should be harmless now that we set
						 * BSDCOMPAT on the socket */
						sleep(1);
					}
				}
			}
		}
#endif
	}
}

int usage(void)
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

	if ((result = (char **) malloc(sizeof(char *) * (n + 2))) == NULL) {
		printf("Sorry, can't get enough memory, exiting.\n");
		exit(1);
	}

	/*
	 * We now can assume that the first and last
	 * characters are different from any delimiters,
	 * so we don't have to care about this.
	 */
	m = 0;
	while ((q = strchr(p, LIST_DELIMITER)) && m < n) {
		result[m] = (char *) malloc((q - p + 1) * sizeof(char));
		if (result[m] == NULL) {
			printf("Sorry, can't get enough memory, exiting.\n");
			exit(1);
		}
		memcpy(result[m], p, q - p);
		result[m][q - p] = '\0';
		p                = q;
		p++;
		m++;
	}
	if ((result[m] = strdup(p)) == NULL) {
		printf("Sorry, can't get enough memory, exiting.\n");
		exit(1);
	}
	result[++m] = NULL;

	return result;
}

void untty(void)
{
	if (!Debug) {
		setsid();
	}
}

/*
 * Parse the line to make sure that the msg is not a composite of more
 * than one message.
 */

void printchopped(const struct sourceinfo *const source, char *msg, size_t len, int fd)
{
	auto int ptlngth;

	auto char *start = msg,
	          *p,
	          *end,
	          tmpline[MAXLINE + 1];

	verbosef("Message length: %lu, File descriptor: %d.\n", (unsigned long) len, fd);
	tmpline[0] = '\0';
	if (parts[fd] != (char *) 0) {
		verbosef("Including part from messages.\n");
		strcpy(tmpline, parts[fd]);
		free(parts[fd]);
		parts[fd] = (char *) 0;
		if ((strlen(msg) + strlen(tmpline)) > MAXLINE) {
			logerror("Cannot glue message parts together");
			printline(source, tmpline);
			start = msg;
		} else {
			verbosef("Previous: %s\n", tmpline);
			verbosef("Next: %s\n", msg);
			strcat(tmpline, msg); /* length checked above */
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
		if ((parts[fd] = malloc(ptlngth + 1)) == (char *) 0)
			logerror("Cannot allocate memory for message part.");
		else {
			strcpy(parts[fd], p);
			verbosef("Saving partial msg: %s\n", parts[fd]);
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
	register unsigned char c;
	char line[MAXLINE + 1];
	unsigned int pri; // Valid Priority values are 0-191
	int prilen = 0;   // Track Priority value string len
	int msglen;

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
char *textpri(int pri)
{
	static char res[20];
	CODE *c_pri, *c_fac;

	for (c_fac = facilitynames; c_fac->c_name && !(c_fac->c_val == LOG_FAC(pri) << 3); c_fac++)
		;
	for (c_pri = prioritynames; c_pri->c_name && !(c_pri->c_val == LOG_PRI(pri)); c_pri++)
		;

	snprintf(res, sizeof(res), "%s.%s<%d>", c_fac->c_name, c_pri->c_name, pri);

	return res;
}

static time_t now;

/*
 * Log a message to the appropriate log files, users, etc. based on
 * the priority.
 */

void logmsg(int pri, const char *msg, const struct sourceinfo *const from, int flags)
{
	register struct filed *f;
	int fac, prilev, lognum;
	int msglen;
	char *timestamp;
	char newmsg[MAXLINE + 1];
	sigset_t mask;

	verbosef("logmsg: %s, flags %x, from %s, msg %s\n", textpri(pri), flags, from->hostname, msg);

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGALRM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

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

	(void) time(&now);
	timestamp = ctime(&now) + 4;

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
		strncat(tag, msg, sizeof(tag) - 1);

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
				goto finish;
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
				goto finish;
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
		if (from->uid != 0) {
			int newlen = strlen(newmsg);
			snprintf(newmsg + newlen, sizeof(newmsg) - newlen,
			         "(uid=%u) ", from->uid);
		}
		/* XXX: Silent truncation is possible */
		strncat(newmsg, msg, sizeof(newmsg) - 1 - strlen(newmsg));
		msg    = newmsg;
		msglen = strlen(msg);
	}

	/* log the message to the particular outputs */
	if (!Initialized) {
		f = &consfile;

		f->f_file = open(ctty, O_WRONLY | O_NOCTTY);

		if (f->f_file >= 0) {
			untty();
			fprintlog(f, (char *) from->hostname, flags, msg);
			(void) close(f->f_file);
			f->f_file = -1;
		}
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		return;
	}

	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];

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
		if (Compress && (flags & MARK) == 0 && msglen == f->f_prevlen &&
		    !strcmp(msg, f->f_prevline) &&
		    !strcmp(from->hostname, f->f_prevhost)) {
			(void) strncpy(f->f_lasttime, timestamp, 15);
			f->f_prevcount++;
			verbosef("msg repeated %d times, %ld sec of %ld.\n",
			         f->f_prevcount, now - f->f_time,
			         (long) repeatinterval[f->f_repeatcount]);

			if (f->f_prevcount == 1 && DupesPending++ == 0) {
				int seconds;
				verbosef("setting alarm to flush duplicate messages\n");

				seconds = alarm(0);
				MarkSeq += LastAlarm - seconds;
				LastAlarm = seconds;
				if (LastAlarm > TIMERINTVL)
					LastAlarm = TIMERINTVL;
				alarm(LastAlarm);
			}

			/*
			 * If domark would have logged this by now,
			 * flush it now (so we don't hold isolated messages),
			 * but back off so we'll flush less often
			 * in the future.
			 */
			if (now > REPEATTIME(f)) {
				fprintlog(f, (char *) from->hostname, flags, (char *) NULL);
				BACKOFF(f);
			}
		} else {
			/* new line, save it */
			if (f->f_prevcount) {
				fprintlog(f, (char *) from->hostname, 0, (char *) NULL);

				if (--DupesPending == 0) {
					verbosef("unsetting duplicate message flush alarm\n");

					MarkSeq += LastAlarm - alarm(0);
					LastAlarm = MarkInterval - MarkSeq;
					alarm(LastAlarm);
				}
			}

			f->f_prevpri     = pri;
			f->f_repeatcount = 0;

			(void) strncpy(f->f_lasttime, timestamp, 15);
			(void) strncpy(f->f_prevhost, from->hostname,
			               sizeof(f->f_prevhost));

			if (msglen < MAXSVLINE) {
				f->f_prevlen = msglen;
				(void) strcpy(f->f_prevline, msg);
				fprintlog(f, (char *) from->hostname, flags, (char *) NULL);
			} else {
				f->f_prevline[0] = 0;
				f->f_prevlen     = 0;
				fprintlog(f, (char *) from->hostname, flags, msg);
			}
		}
	}
finish:
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

char *get_record_field(struct log_format *log_fmt, enum log_format_type name)
{
	if (!(log_fmt->f_mask | (1 << name)))
		return NULL;

	for (int i = 0; i < LOG_FORMAT_FIELDS_MAX && log_fmt->fields[i].f_iov; i++) {
		if (log_fmt->fields[i].f_type == name)
			return log_fmt->fields[i].f_iov->iov_base;
	}
	return NULL;
}

void set_record_field(struct log_format *log_fmt,
                      enum log_format_type name, const char *value, ssize_t len)
{
	size_t iov_len;

	if (!(log_fmt->f_mask | (1 << name)))
		return;

	iov_len = len == -1 ? strlen(value) : len;

	for (int i = 0; i < LOG_FORMAT_FIELDS_MAX && log_fmt->fields[i].f_iov; i++) {
		if (log_fmt->fields[i].f_type == name) {
			log_fmt->fields[i].f_iov->iov_base = (void *) value;
			log_fmt->fields[i].f_iov->iov_len  = iov_len;
		}
	}
}

void clear_record_fields(struct log_format *log_fmt)
{
	for (int i = 0; i < LOG_FORMAT_FIELDS_MAX && log_fmt->fields[i].f_iov; i++) {
		log_fmt->fields[i].f_iov->iov_base = NULL;
		log_fmt->fields[i].f_iov->iov_len  = 0;
	}
}

void calculate_digest(struct filed *f, struct log_format *log_fmt)
{
	int i, n;
	unsigned char digest[HASH_RAWSZ];
	hash_ctx_t hash_ctx;

	if (!(log_fmt->f_mask | (1 << LOG_FORMAT_HASH)))
		return;

	digest[0] = 0;

	hash_init(&hash_ctx);
	for (i = 0; i < LOG_FORMAT_IOVEC_MAX; i++)
		hash_update(&hash_ctx, log_fmt->iov[i].iov_base, log_fmt->iov[i].iov_len);
	hash_final(digest, &hash_ctx);

	strncpy(f->f_prevhash, HASH_NAME, sizeof(f->f_prevhash));
	n = HASH_NAMESZ;

	strncpy(f->f_prevhash + n, ":", sizeof(f->f_prevhash) - n);
	n += 1;

	for (i = 0; i < HASH_RAWSZ; i++) {
		snprintf(f->f_prevhash + n, sizeof(f->f_prevhash) - n, "%02x", digest[i]);
		n += 2;
	}
	f->f_prevhash[n] = 0;
	return;
}

void fprintlog(struct filed *f, char *from, int flags, const char *msg)
{
	char repbuf[80];
#ifdef SYSLOG_INET
	register int l;
	char line[MAXLINE + 1];
	time_t fwd_suspend;
	struct addrinfo hints, *ai;
	int err;
#endif

	verbosef("Called fprintlog, ");

	clear_record_fields(&log_fmt);

	set_record_field(&log_fmt, LOG_FORMAT_TIME, f->f_lasttime, 15);
	set_record_field(&log_fmt, LOG_FORMAT_HOST, f->f_prevhost, -1);
	set_record_field(&log_fmt, LOG_FORMAT_HASH, f->f_prevhash, -1);
	if (msg) {
		set_record_field(&log_fmt, LOG_FORMAT_MSG, msg, -1);
	} else if (f->f_prevcount > 1) {
		(void) snprintf(repbuf, sizeof(repbuf), "last message repeated %d times",
		                f->f_prevcount);
		set_record_field(&log_fmt, LOG_FORMAT_MSG, repbuf, -1);
	} else {
		set_record_field(&log_fmt, LOG_FORMAT_MSG, f->f_prevline, f->f_prevlen);
	}

	verbosef("logging to %s", TypeNames[f->f_type]);

	switch (f->f_type) {
		case F_UNUSED:
			f->f_time = now;
			verbosef("\n");
			break;

#ifdef SYSLOG_INET
		case F_FORW_SUSP:
			fwd_suspend = time((time_t *) 0) - f->f_time;
			if (fwd_suspend >= INET_SUSPEND_TIME) {
				verbosef("\nForwarding suspension over, "
				         "retrying FORW ");
				f->f_type = F_FORW;
				goto f_forw;
			} else {
				verbosef(" %s\n", f->f_un.f_forw.f_hname);
				verbosef("Forwarding suspension not over, time "
				         "left: %ld.\n",
				         (long) (INET_SUSPEND_TIME - fwd_suspend));
			}
			break;
		/*
		 * The trick is to wait some time, then retry to get the
		 * address. If that fails retry x times and then give up.
		 *
		 * You'll run into this problem mostly if the name server you
		 * need for resolving the address is on the same machine, but
		 * is started after syslogd.
		 */
		case F_FORW_UNKN:
			verbosef(" %s\n", f->f_un.f_forw.f_hname);
			fwd_suspend = time((time_t *) 0) - f->f_time;
			if (fwd_suspend >= INET_SUSPEND_TIME) {
				verbosef("Forwarding suspension to unknown over, retrying\n");
				memset(&hints, 0, sizeof(hints));
				hints.ai_family   = family;
				hints.ai_socktype = SOCK_DGRAM;
				if ((err = getaddrinfo(f->f_un.f_forw.f_hname, "syslog", &hints, &ai))) {
					verbosef("Failure: %s\n", gai_strerror(err));
					verbosef("Retries: %d\n", f->f_prevcount);
					if (--f->f_prevcount < 0) {
						verbosef("Giving up.\n");
						f->f_type = F_UNUSED;
					} else
						verbosef("Left retries: %d\n", f->f_prevcount);
				} else {
					verbosef("%s found, resuming.\n", f->f_un.f_forw.f_hname);
					f->f_un.f_forw.f_addr = ai;
					f->f_prevcount        = 0;
					f->f_type             = F_FORW;
					goto f_forw;
				}
			} else
				verbosef("Forwarding suspension not over, time "
				         "left: %ld\n",
				         (long) (INET_SUSPEND_TIME - fwd_suspend));
			break;

		case F_FORW:
			/*
			 * Don't send any message to a remote host if it
			 * already comes from one. (we don't care 'bout who
			 * sent the message, we don't send it anyway)  -Joey
			 */
		f_forw:
			verbosef(" %s\n", f->f_un.f_forw.f_hname);
			if (strcmp(from, LocalHostName) && NoHops)
				verbosef("Not sending message to remote.\n");
			else if (finet) {
				int i;
				f->f_time = now;
				(void) snprintf(line, sizeof(line), "<%d>%s", f->f_prevpri,
				                (char *) log_fmt.iov[LOG_FORMAT_MSG].iov_base);
				l = strlen(line);
				if (l > MAXLINE)
					l = MAXLINE;
				err = -1;
				for (ai = f->f_un.f_forw.f_addr; ai; ai = ai->ai_next) {
					for (i = 0; i < *finet; i++) {
						int lsent;
						lsent = sendto(finet[i + 1], line, l, 0,
						               ai->ai_addr, ai->ai_addrlen);
						if (lsent == l) {
							err = -1;
							break;
						}
						err = errno;
					}
					if (err == -1 && !send_to_all)
						break;
				}
				if (err != -1) {
					verbosef("INET sendto error: %d = %s.\n",
					         err, strerror(err));
					f->f_type = F_FORW_SUSP;
					errno     = err;
					logerror("sendto");
				}
			}
			break;
#endif

		case F_CONSOLE:
			f->f_time = now;
#ifdef UNIXPC
			if (1) {
#else
			if (flags & IGN_CONS) {
#endif
				verbosef(" (ignored).\n");
				break;
			}
			/* FALLTHROUGH */

		case F_TTY:
		case F_FILE:
		case F_PIPE:
			f->f_time = now;
			verbosef(" %s\n", f->f_un.f_fname);
			if (f->f_type == F_TTY || f->f_type == F_CONSOLE) {
				set_record_field(&log_fmt, LOG_FORMAT_EOL, "\r\n", 2);
			} else {
				set_record_field(&log_fmt, LOG_FORMAT_EOL, "\n", 1);
			}
		again:
			/*
			 * f->f_file == -1 is an indicator that we couldn't
			 * open the file at startup.
			 */
			if (f->f_file == -1)
				break;

			calculate_digest(f, &log_fmt);

			if (writev(f->f_file, log_fmt.iov, LOG_FORMAT_IOVEC_MAX) < 0) {
				int e = errno;

				/* If a named pipe is full, just ignore it for now */
				if ((f->f_type == F_PIPE || f->f_type == F_TTY) && e == EAGAIN)
					break;

				/*
				 * If the filesystem is filled up, just ignore
				 * it for now and continue writing when
				 * possible
				 */
				if (f->f_type == F_FILE && e == ENOSPC)
					break;

				(void) close(f->f_file);
				/*
				 * Check for EBADF on TTY's due to vhangup() XXX
				 * Linux uses EIO instead (mrn 12 May 96)
				 */
				if ((f->f_type == F_TTY || f->f_type == F_CONSOLE)
#ifdef linux
				    && e == EIO) {
#else
				    && e == EBADF) {
#endif
					f->f_file = open(f->f_un.f_fname, O_WRONLY | O_APPEND | O_NOCTTY);
					if (f->f_file < 0) {
						f->f_type = F_UNUSED;
						logerror(f->f_un.f_fname);
					} else {
						untty();
						goto again;
					}
					if (f->f_type == F_TTY)
						(void) set_nonblock_flag(f->f_file);
				} else {
					f->f_type = F_UNUSED;
					errno     = e;
					logerror(f->f_un.f_fname);
				}
			} else if (f->f_type == F_FILE && (f->f_flags & SYNC_FILE))
				(void) fsync(f->f_file);
			break;

		case F_USERS:
		case F_WALL:
			f->f_time = now;
			verbosef("\n");
			set_record_field(&log_fmt, LOG_FORMAT_EOL, "\r\n", 2);
			calculate_digest(f, &log_fmt);
			wallmsg(f, &log_fmt);
			break;
	} /* switch */
	if (f->f_type != F_FORW_UNKN)
		f->f_prevcount = 0;
	return;
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
void wallmsg(struct filed *f, struct log_format *log_fmt)
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
		(void) signal(SIGTERM, SIG_DFL);
		(void) alarm(0);

		if (f->f_type == F_WALL) {
			snprintf(greetings, sizeof(greetings),
			         "\r\n\7Message from syslogd@%s at %.24s ...\r\n",
			         get_record_field(log_fmt, LOG_FORMAT_HOST), ctime(&now));

			set_record_field(log_fmt, LOG_FORMAT_BOL, greetings, -1);
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
					if (strncmp(f->f_un.f_uname[i],
					            ut.ut_name, UNAMESZ) == 0)
						break;
				}
				if (i >= MAXUNAMES)
					continue;
			}

			/* compute the device name */
			strcpy(p, _PATH_DEV);
			strncat(p, ut.ut_line, UNAMESZ);

			if (setjmp(ttybuf) == 0) {
				(void) signal(SIGALRM, endtty);
				(void) alarm(15);
				/* open the terminal */
				ttyf = open(p, O_WRONLY | O_NOCTTY);
				if (ttyf >= 0) {
					struct stat statb;

					if (!fstat(ttyf, &statb) && (statb.st_mode & S_IWRITE)) {
						if (writev(ttyf, log_fmt->iov, LOG_FORMAT_IOVEC_MAX) < 0)
							errno = 0; /* ignore */
					}
					close(ttyf);
					ttyf = -1;
				}
			}
			(void) alarm(0);
		}
		exit(0);
	}
	/* close the user login file */
	endutent();
	reenter = 0;
}

void reapchild(int sig)
{
	int saved_errno = errno;
	int status;

	while (wait3(&status, WNOHANG, (struct rusage *) NULL) > 0)
		;
	(void) signal(SIGCHLD, reapchild); /* reset signal handler -ASP */
	errno = saved_errno;
}

const char *cvtaddr(struct sockaddr_storage *f, int len)
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
const char *cvthname(struct sockaddr_storage *f, int len)
{
	static char hname[NI_MAXHOST];
	int error;
	register char *p;
	int count;

	if ((error = getnameinfo((struct sockaddr *) f, len,
	                         hname, NI_MAXHOST, NULL, 0, NI_NAMEREQD))) {
		verbosef("Host name for your address (%s) unknown: %s\n", hname, gai_strerror(error));
		if ((error = getnameinfo((struct sockaddr *) f, len,
		                         hname, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))) {
			verbosef("Malformed from address: %s\n", gai_strerror(error));
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

void domark(int sig)
{
	register struct filed *f;
	int lognum;
	struct sourceinfo source;

	memset(&source, '\0', sizeof(source));

	source.flags    = SINFO_ISINTERNAL;
	source.hostname = LocalHostName;

	if (MarkInterval > 0) {
		now = time(NULL);
		MarkSeq += LastAlarm;
		if (MarkSeq >= MarkInterval) {
			logmsg(LOG_MARK | LOG_INFO, "-- MARK --", &source, ADDDATE | MARK);
			MarkSeq -= MarkInterval;
		}
	}

	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];

		if (f->f_prevcount && now >= REPEATTIME(f)) {
			verbosef("flush %s: repeated %d times, %ld sec.\n",
			         TypeNames[f->f_type], f->f_prevcount,
			         (long) repeatinterval[f->f_repeatcount]);
			fprintlog(f, LocalHostName, 0, (char *) NULL);
			BACKOFF(f);
			DupesPending--;
		}
	}
	(void) signal(SIGALRM, domark);

	LastAlarm = MarkInterval - MarkSeq;
	if (DupesPending && LastAlarm > TIMERINTVL)
		LastAlarm = TIMERINTVL;

	(void) alarm(LastAlarm);
}

void debug_switch(int sig)
{
	verbosef("Switching debugging_on to %s\n", (debugging_on == 0) ? "true" : "false");
	debugging_on = (debugging_on == 0) ? 1 : 0;
	signal(SIGUSR1, debug_switch);
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

	strncpy(buf, "syslogd: ", sizeof(buf));

	va_start(ap, fmt);
	vsnprintf(buf + 9, sizeof(buf) - 9, fmt, ap);
	va_end(ap);

	verbosef("Called logerror: %s\n", buf);

	if (sv_errno != 0) {
		size_t bufsz = strlen(buf);
		if (strerror_r(sv_errno, buf + bufsz, sizeof(buf) - bufsz))
			errno = 0; // ignore
	}

	if (!LogFormatInitialized) {
		fputs(buf, stderr);
		return;
	}

	memset(&source, '\0', sizeof(source));

	source.flags    = SINFO_ISINTERNAL;
	source.hostname = LocalHostName;

	logmsg(LOG_SYSLOG | LOG_ERR, buf, &source, ADDDATE);
	errno = 0;
	return;
}

void die(int sig)
{
	register struct filed *f;
	char buf[100];
	int lognum;
	int i;
	int was_initialized = Initialized;
	struct sourceinfo source;

	memset(&source, '\0', sizeof(source));

	source.flags    = SINFO_ISINTERNAL;
	source.hostname = LocalHostName;

	Initialized = 0; /* Don't log SIGCHLDs in case we
			   receive one during exiting */

	for (lognum = 0; lognum <= nlogs; lognum++) {
		f = &Files[lognum];
		/* flush any pending output */
		if (f->f_prevcount)
			fprintlog(f, LocalHostName, 0, (char *) NULL);
	}

	Initialized = was_initialized;
	if (sig) {
		verbosef("syslogd: exiting on signal %d\n", sig);
		(void) snprintf(buf, sizeof(buf), "exiting on signal %d", sig);
		errno = 0;
		logmsg(LOG_SYSLOG | LOG_INFO, buf, &source, ADDDATE);
	}

	/* Close the UNIX sockets. */
	for (i = 0; i < nfunix; i++)
		if (funix[i] != -1)
			close(funix[i]);
	/* Close the inet sockets. */
	if (InetInuse && finet) {
		for (i = 0; i < *finet; i++)
			close(finet[i + 1]);
		free(finet);
	}

	/* Clean-up files. */
	for (i = 0; i < nfunix; i++)
		if (funixn[i] && funix[i] != -1)
			(void) unlink(funixn[i]);

	(void) remove_pid(PidFile);

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
	register FILE *cf;
	register struct filed *f;
	register char *p;
	register unsigned int Forwarding = 0;
	char cbuf[BUFSIZ];
	char *cline;
	struct hostent *hent;
	struct sourceinfo source;

	memset(&source, '\0', sizeof(source));

	source.flags    = SINFO_ISINTERNAL;
	source.hostname = LocalHostName;

	/*
	 *  Close all open log files and free log descriptor array.
	 */
	verbosef("Called init.\n");
	Initialized = 0;
	if (nlogs > -1) {
		verbosef("Initializing log structures.\n");

		for (lognum = 0; lognum <= nlogs; lognum++) {
			f = &Files[lognum];

			/* flush any pending output */
			if (f->f_prevcount)
				fprintlog(f, LocalHostName, 0, (char *) NULL);

			switch (f->f_type) {
				case F_FILE:
				case F_PIPE:
				case F_TTY:
				case F_CONSOLE:
					(void) close(f->f_file);
					break;
				case F_FORW:
				case F_FORW_SUSP:
					freeaddrinfo(f->f_un.f_forw.f_addr);
					break;
			}
		}

		/*
		 * This is needed especially when HUPing syslogd as the
		 * structure would grow infinitively.  -Joey
		 */
		nlogs = -1;
		free((void *) Files);
		Files = (struct filed *) 0;
	}

	lognum = 0;

	/* Get hostname */
	(void) gethostname(LocalHostName, sizeof(LocalHostName));
	LocalDomain = emptystring;
	if ((p = strchr(LocalHostName, '.'))) {
		*p++        = '\0';
		LocalDomain = p;
	} else if (AcceptRemote) {
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

	/* open the configuration file */
	if ((cf = fopen(ConfFile, "r")) == NULL) {
		verbosef("cannot open %s.\n", ConfFile);
		allocate_log();
		f = &Files[lognum++];

		cfline("*.err\t" _PATH_CONSOLE, f);

		Initialized = 1;
		return;
	}

	/*
	 *  Foreach line in the conf table, open that file.
	 */
	cline = cbuf;
	while (fgets(cline, sizeof(cbuf) - (cline - cbuf), cf) != NULL) {
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

		if (!strncmp("log_format:", cline, 11)) {
			for (p = cline + 11; isspace(*p); ++p)
				;
			parse_log_format(&log_fmt, p);
			continue;
		}

		allocate_log();
		f = &Files[lognum++];

		cfline(cbuf, f);

		if (f->f_type == F_FORW || f->f_type == F_FORW_SUSP || f->f_type == F_FORW_UNKN) {
			Forwarding++;
		}
	}

	/* close the configuration file */
	(void) fclose(cf);

#ifdef SYSLOG_UNIXAF
	for (i = 0; i < nfunix; i++) {
		if (funix[i] != -1)
			/*
			 * Don't close the socket, preserve it instead
			 * close(funix[i]);
			 */
			continue;
		if ((funix[i] = create_unix_socket(funixn[i])) != -1)
			verbosef("Opened UNIX socket `%s'.\n", funixn[i]);
	}
#endif

#ifdef SYSLOG_INET
	if (Forwarding || AcceptRemote) {
		if (!finet) {
			finet = create_inet_sockets();
			if (finet) {
				InetInuse = 1;
				verbosef("Opened syslog UDP port.\n");
			}
		}
	} else {
		if (finet) {
			for (i = 0; i < *finet; i++)
				if (finet[i + 1] != -1)
					close(finet[i + 1]);
			free(finet);
			finet = NULL;
		}
		InetInuse = 0;
	}
#endif

	Initialized = 1;

	if (Debug) {
		for (lognum = 0; lognum <= nlogs; lognum++) {
			f = &Files[lognum];
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
				}
				printf("\n");
			}
		}
	}

	if (AcceptRemote)
		logmsg(LOG_SYSLOG | LOG_INFO, "syslogd " VERSION "." PATCHLEVEL ": restart (remote reception).", &source, ADDDATE);
	else
		logmsg(LOG_SYSLOG | LOG_INFO, "syslogd " VERSION "." PATCHLEVEL ": restart.", &source, ADDDATE);

	(void) signal(SIGHUP, sighup_handler);
	verbosef("syslogd: restarted.\n");
}

/*
 * Crack a configuration file line
 */
void cfline(const char *line, struct filed *f)
{
	register const char *p;
	register const char *q;
	register int i, i2;
	char *bp;
	int pri;
	int singlpri  = 0;
	int ignorepri = 0;
	int syncfile;
#ifdef SYSLOG_INET
	struct addrinfo hints, *ai;
#endif
	char buf[MAXLINE];

	verbosef("cfline(%s)\n", line);

	errno = 0; /* keep strerror() stuff out of logerror messages */

	for (i = 0; i <= LOG_NFACILITIES; i++) {
		f->f_pmask[i] = TABLE_NOPRI;
		f->f_flags    = 0;
	}

	/* scan through the list of selectors */
	for (p = line; *p && *p != '\t' && *p != ' ';) {

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
			ignorepri = 1;
			for (bp = buf; *(bp + 1); bp++)
				*bp = *(bp + 1);
			*bp = '\0';
		} else {
			ignorepri = 0;
		}
		if (*buf == '=') {
			singlpri = 1;
			pri      = decode(&buf[1], PriNames);
		} else {
			singlpri = 0;
			pri      = decode(buf, PriNames);
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
				for (i = 0; i <= LOG_NFACILITIES; i++) {
					if (pri == INTERNAL_NOPRI) {
						if (ignorepri)
							f->f_pmask[i] = TABLE_ALLPRI;
						else
							f->f_pmask[i] = TABLE_NOPRI;
					} else if (singlpri) {
						if (ignorepri)
							f->f_pmask[i] &= ~(1 << pri);
						else
							f->f_pmask[i] |= (1 << pri);
					} else {
						if (pri == TABLE_ALLPRI) {
							if (ignorepri)
								f->f_pmask[i] = TABLE_NOPRI;
							else
								f->f_pmask[i] = TABLE_ALLPRI;
						} else {
							if (ignorepri)
								for (i2 = 0; i2 <= pri; ++i2)
									f->f_pmask[i] &= ~(1 << i2);
							else
								for (i2 = 0; i2 <= pri; ++i2)
									f->f_pmask[i] |= (1 << i2);
						}
					}
				}
			} else {
				i = decode(buf, FacNames);
				if (i < 0) {

					logerror("unknown facility name \"%s\"", buf);
					return;
				}

				if (pri == INTERNAL_NOPRI) {
					if (ignorepri)
						f->f_pmask[i >> 3] = TABLE_ALLPRI;
					else
						f->f_pmask[i >> 3] = TABLE_NOPRI;
				} else if (singlpri) {
					if (ignorepri)
						f->f_pmask[i >> 3] &= ~(1 << pri);
					else
						f->f_pmask[i >> 3] |= (1 << pri);
				} else {
					if (pri == TABLE_ALLPRI) {
						if (ignorepri)
							f->f_pmask[i >> 3] = TABLE_NOPRI;
						else
							f->f_pmask[i >> 3] = TABLE_ALLPRI;
					} else {
						if (ignorepri)
							for (i2 = 0; i2 <= pri; ++i2)
								f->f_pmask[i >> 3] &= ~(1 << i2);
						else
							for (i2 = 0; i2 <= pri; ++i2)
								f->f_pmask[i >> 3] |= (1 << i2);
					}
				}
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

	verbosef("leading char in action: %c\n", *p);
	switch (*p) {
		case '@':
#ifdef SYSLOG_INET
			(void) strcpy(f->f_un.f_forw.f_hname, ++p);
			verbosef("forwarding host: %s\n", p); /*ASP*/
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
			(void) strcpy(f->f_un.f_fname, p);
			verbosef("filename: %s\n", p); /*ASP*/
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
				logerror("Error opening log file: %s", p);
				break;
			}
			if (isatty(f->f_file)) {
				(void) set_nonblock_flag(f->f_file);
				f->f_type = F_TTY;
				untty();
			}
			if (strcmp(p, ctty) == 0)
				f->f_type = F_CONSOLE;
			break;

		case '*':
			verbosef("write-all\n");
			f->f_type = F_WALL;
			break;

		default:
			verbosef("users: %s\n", p); /* ASP */
			for (i = 0; i < MAXUNAMES && *p; i++) {
				for (q = p; *q && *q != ',';)
					q++;
				(void) strncpy(f->f_un.f_uname[i], p, UNAMESZ);
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

/*
 *  Decode a symbolic name to a numeric value
 */
int decode(char *name, struct code *codetab)
{
	register struct code *c;
	register char *p;
	char buf[80];

	verbosef("symbolic name: %s", name);
	if (isdigit(*name)) {
		verbosef("\n");
		return (atoi(name));
	}
	(void) strncpy(buf, name, 79);
	for (p = buf; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);
	for (c = codetab; c->c_name; c++)
		if (!strcmp(buf, c->c_name)) {
			verbosef(" ==> %d\n", c->c_val);
			return (c->c_val);
		}
	return (-1);
}

void verbosef(const char *fmt, ...)
{
	va_list ap;

	if (!(Debug && debugging_on))
		return;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	fflush(stdout);
	return;
}

/*
 * The following function is responsible for allocating/reallocating the
 * array which holds the structures which define the logging outputs.
 */
void allocate_log(void)
{
	verbosef("Called allocate_log, nlogs = %d.\n", nlogs);

	/*
	 * Decide whether the array needs to be initialized or needs to
	 * grow.
	 */
	if (nlogs == -1) {
		Files = (struct filed *) malloc(sizeof(struct filed));
		if (Files == (void *) 0) {
			logerror("Cannot initialize log structure.");
			return;
		}
	} else {
		/* Re-allocate the array. */
		Files = (struct filed *) realloc(Files, (nlogs + 2) *
		                                            sizeof(struct filed));
		if (Files == (struct filed *) 0) {
			logerror("Cannot grow log structure.");
			return;
		}
	}

	/*
	 * Initialize the array element, bump the number of elements in the
	 * the array and return.
	 */
	++nlogs;
	memset(&Files[nlogs], '\0', sizeof(struct filed));
	strncpy(Files[nlogs].f_prevhash, EMPTY_HASH_LITERAL, sizeof(Files[nlogs].f_prevhash));
	return;
}

int set_log_format_field(struct log_format *log_fmt, size_t i,
                         enum log_format_type t, const char *s, size_t n)
{
	if (i >= iovec_max) {
		logerror("Too many parts in the log_format string");
		return -1;
	}

	if (t != LOG_FORMAT_NONE) {
		if (log_fmt->fields_nr >= LOG_FORMAT_FIELDS_MAX) {
			logerror("Too many placeholders in the log_format string");
			return -1;
		}

		log_fmt->f_mask |= (1 << t);
		log_fmt->fields[log_fmt->fields_nr].f_type = t;
		log_fmt->fields[log_fmt->fields_nr].f_iov  = log_fmt->iov + i;
		log_fmt->fields_nr++;
	}

	log_fmt->iov[i].iov_base = (void *) s;
	log_fmt->iov[i].iov_len  = n;
	log_fmt->iovec_nr++;

	return 0;
}

int parse_log_format(struct log_format *log_fmt, const char *str)
{
	const char *ptr, *start;
	int i, special, field_nr;
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
		                         LOG_FORMAT_NONE, start, (ptr - start - 1)) < 0)
			goto error;

		if (set_log_format_field(&new_fmt, field_nr++, f_type, NULL, 0) < 0)
			goto error;

		start = ptr + 1;
		goto next;
	create_special:
		if (set_log_format_field(&new_fmt, field_nr++,
		                         LOG_FORMAT_NONE, start, (ptr - start - 1)) < 0)
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
	                         LOG_FORMAT_NONE, start, (ptr - start)) < 0)
		goto error;

	if (set_log_format_field(&new_fmt, field_nr++,
	                         LOG_FORMAT_EOL, NULL, 0) < 0)
		goto error;

	log_fmt->line   = new_fmt.line;
	log_fmt->iov    = new_fmt.iov;
	log_fmt->fields = new_fmt.fields;

	LogFormatInitialized = 1;

	return 0;
error:
	free(new_fmt.line);
	free(new_fmt.iov);
	free(new_fmt.fields);

	return -1;
}

/*
 * The following function is resposible for handling a SIGHUP signal.  Since
 * we are now doing mallocs/free as part of init we had better not being
 * doing this during a signal handler.  Instead this function simply sets
 * a flag variable which will tell the main loop to go through a restart.
 */
void sighup_handler(int sig)
{
	restart = 1;
	signal(SIGHUP, sighup_handler);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
