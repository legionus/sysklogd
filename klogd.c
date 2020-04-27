/*
    klogd.c - main program for Linux kernel log daemon.
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

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#if !defined(__GLIBC__)
#include <linux/time.h>
#endif /* __GLIBC__ */
#include <stdarg.h>
#include <paths.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include "klogd.h"
#include "ksyms.h"
#include "pidfile.h"
#include "version.h"

#define __LIBRARY__
#include <linux/unistd.h>
#if !defined(__GLIBC__)
# define __NR_ksyslog __NR_syslog
_syscall3(int,ksyslog,int, type, char *, buf, int, len);
#else
#include <sys/klog.h>
#define ksyslog klogctl
#endif

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL	"/dev/null"
#endif

#define LOG_BUFFER_SIZE 4096
#define LOG_LINE_LENGTH 1000

#if defined(FSSTND)
static char	*PidFile = _PATH_VARRUN "klogd.pid";
#else
static char	*PidFile = "/etc/klogd.pid";
#endif

static int	kmsg,
		change_state = 0,
		terminate = 0,
		caught_TSTP = 0,
		reload_symbols = 0,
		console_log_level = -1;

static int	use_syscall = 0,
		one_shot = 0,
		symbol_lookup = 1,
		no_fork = 0;	/* don't fork - don't run in daemon mode */

static char	*symfile = (char *) 0,
		log_buffer[LOG_BUFFER_SIZE];

static FILE *output_file = (FILE *) 0;

static enum LOGSRC {none, proc, kernel} logsrc;

int debugging = 0;
static int symbols_twice = 0;

static char *server_user = NULL;
static char *chroot_dir = NULL;
static int log_flags = 0;

/* Function prototypes. */
extern int ksyslog(int type, char *buf, int len);
static void CloseLogSrc(void);
static void Terminate(void);
static void SignalDaemon(int);
static void ReloadSymbols(void);
static void ChangeLogging(void);
static enum LOGSRC GetKernelLogSrc(void);
static void LogLine(char *ptr, int len);
static void LogKernelLine(void);
static void LogProcLine(void);
extern int main(int argc, char *argv[]);


static void CloseLogSrc(void)
{
        /* Shutdown the log sources. */
	switch ( logsrc )
	{
	    case kernel:
		ksyslog(0, 0, 0);
		Syslog(LOG_INFO, "Kernel logging (ksyslog) stopped.");
		break;
            case proc:
		close(kmsg);
		Syslog(LOG_INFO, "Kernel logging (proc) stopped.");
		break;
	    case none:
		break;
	}

	if ( output_file != (FILE *) 0 )
		fflush(output_file);
	return;
}


/*
 * Signal handler to terminate the parent process.
 */
static void doexit(int sig)
{
	exit (0);
}

static void restart(int sig)
{
	signal(SIGCONT, restart);
	change_state = 1;
	caught_TSTP = 0;
	return;
}


static void stop_logging(int sig)
{
	signal(SIGTSTP, stop_logging);
	change_state = 1;
	caught_TSTP = 1;
	return;
}


static void stop_daemon(int sig)
{
	Terminate();
	return;
}


static void reload_daemon(int sig)
{
	change_state = 1;
	reload_symbols = 1;

	if ( sig == SIGUSR2 )
	{
		++reload_symbols;
		signal(SIGUSR2, reload_daemon);
	}
	else
		signal(SIGUSR1, reload_daemon);

	return;
}


static void Terminate(void)
{
	CloseLogSrc();
	Syslog(LOG_INFO, "Kernel log daemon terminating.");
	sleep(1);
	if ( output_file != (FILE *) 0 )
		fclose(output_file);
	closelog();
	(void) remove_pid(PidFile);
	exit(1);
}

static void SignalDaemon(int sig)
{
	int pid = check_pid(PidFile);
	kill(pid, sig);
}


static void ReloadSymbols(void)
{
	if (symbol_lookup) {
		if ( reload_symbols > 1 )
			InitKsyms(symfile);
		InitMsyms();
	}
	reload_symbols = change_state = 0;
}


static void ChangeLogging(void)
{
	/* Terminate kernel logging. */
	if ( terminate == 1 )
		Terminate();

	/* Indicate that something is happening. */
	Syslog(LOG_INFO, "klogd %s.%s, ---------- state change ----------\n", \
	       VERSION, PATCHLEVEL);

	/* Reload symbols. */
	if ( reload_symbols > 0 )
	{
		ReloadSymbols();
		return;
	}

	/* Stop kernel logging. */
	if ( caught_TSTP == 1 )
	{
		CloseLogSrc();
		logsrc = none;
		change_state = 0;
		return;
	}

	/*
	 * The rest of this function is responsible for restarting
	 * kernel logging after it was stopped.
	 *
	 * In the following section we make a decision based on the
	 * kernel log state as to what is causing us to restart.  Somewhat
	 * groady but it keeps us from creating another static variable.
	 */
	if ( logsrc != none )
	{
		Syslog(LOG_INFO, "Kernel logging re-started after SIGSTOP.");
		change_state = 0;
		return;
	}

	/* Restart logging. */
	logsrc = GetKernelLogSrc();
	change_state = 0;
	return;
}


static enum LOGSRC GetKernelLogSrc(void)
{
	struct stat sb;

	/* Set level of kernel console messaging.. */
	if ( (console_log_level != -1)
	&& (ksyslog(8, NULL, console_log_level) < 0) && \
	     (errno == EINVAL) )
	{
		/*
		 * An invalid arguement error probably indicates that
		 * a pre-0.14 kernel is being run.  At this point we
		 * issue an error message and simply shut-off console
		 * logging completely.
		 */
		Syslog(LOG_WARNING, "Cannot set console log level - disabling "
		       "console output.");
	}

	/*
	 * First do a stat to determine whether or not the proc based
	 * file system is available to get kernel messages from.
	 */
	if (!server_user &&
	    (use_syscall ||
	    ((stat(_PATH_KLOG, &sb) < 0) && (errno == ENOENT))))
	{
	  	/* Initialize kernel logging. */
	  	ksyslog(1, NULL, 0);
		Syslog(LOG_INFO, "klogd %s.%s, log source = ksyslog "
		       "started.", VERSION, PATCHLEVEL);
		return(kernel);
	}

	if ( (kmsg = open(_PATH_KLOG, O_RDONLY)) < 0 )
	{
		fprintf(stderr, "klogd: Cannot open proc file system, " \
			"%d - %s.\n", errno, strerror(errno));
		ksyslog(7, NULL, 0);
		exit(1);
	}
	Syslog(LOG_INFO, "klogd %s.%s, log source = %s started.", \
	       VERSION, PATCHLEVEL, _PATH_KLOG);
	return(proc);
}

void Syslog(int priority, char *fmt, ...)
{
	va_list ap;
	char *argl;

	if ( debugging )
	{
		fputs("Logging line:\n", stderr);
		fprintf(stderr, "\tLine: %s\n", fmt);
		fprintf(stderr, "\tPriority: %d\n", priority);
	}

	/* Handle output to a file. */
	if ( output_file != (FILE *) 0 )
	{
		va_start(ap, fmt);
		vfprintf(output_file, fmt, ap);
		va_end(ap);
		fputc('\n', output_file);
		fflush(output_file);
		if (!one_shot)
			fsync(fileno(output_file));
		return;
	}

	/* Output using syslog. */
	if (!strcmp(fmt, "%s"))
	{
		va_start(ap, fmt);
		argl = va_arg(ap, char *);
		if (argl[0] == '<' && argl[1] && argl[2] == '>')
		{
			switch ( argl[1] )
			{
			case '0':
				priority = LOG_EMERG;
				break;
			case '1':
				priority = LOG_ALERT;
				break;
			case '2':
				priority = LOG_CRIT;
				break;
			case '3':
				priority = LOG_ERR;
				break;
			case '4':
				priority = LOG_WARNING;
				break;
			case '5':
				priority = LOG_NOTICE;
				break;
			case '6':
				priority = LOG_INFO;
				break;
			case '7':
			default:
				priority = LOG_DEBUG;
			}
			argl += 3;
		}
		syslog(priority, fmt, argl);
		va_end(ap);
		return;
	}

	va_start(ap, fmt);
	vsyslog(priority, fmt, ap);
	va_end(ap);

	return;
}


/*
 *     Copy characters from ptr to line until a char in the delim
 *     string is encountered or until min( space, len ) chars have
 *     been copied.
 *
 *     Returns the actual number of chars copied.
 */
static int copyin( char *line,      int space,
                   const char *ptr, int len,
                   const char *delim )
{
    auto int i;
    auto int count;

    count = len < space ? len : space;

    for(i=0; i<count && !strchr(delim, *ptr); i++ ) { *line++ = *ptr++; }

    return( i );
}

/*
 * Messages are separated by "\n".  Messages longer than
 * LOG_LINE_LENGTH are broken up.
 *
 * Kernel symbols show up in the input buffer as : "[<aaaaaa>]",
 * where "aaaaaa" is the address.  These are replaced with
 * "[symbolname+offset/size]" in the output line - symbolname,
 * offset, and size come from the kernel symbol table.
 *
 * If a kernel symbol happens to fall at the end of a message close
 * in length to LOG_LINE_LENGTH, the symbol will not be expanded.
 * (This should never happen, since the kernel should never generate
 * messages that long.
 *
 * To preserve the original addresses, lines containing kernel symbols
 * are output twice.  Once with the symbols converted and again with the
 * original text.  Just in case somebody wants to run their own Oops
 * analysis on the syslog, e.g. ksymoops.
 */
static void LogLine(char *ptr, int len)
{
    enum parse_state_enum {
        PARSING_TEXT,
        PARSING_SYMSTART,      /* at < */
        PARSING_SYMBOL,
        PARSING_SYMEND         /* at ] */
    };

    static char line_buff[LOG_LINE_LENGTH];

    static char *line                        =line_buff;
    static enum parse_state_enum parse_state = PARSING_TEXT;
    static int space                         = sizeof(line_buff)-1;

    static char *sym_start;            /* points at the '<' of a symbol */

    auto   int delta = 0;              /* number of chars copied        */
    auto   int symbols_expanded = 0;   /* 1 if symbols were expanded */
    auto   int skip_symbol_lookup = 0; /* skip symbol lookup on this pass */
    auto   char *save_ptr = ptr;       /* save start of input line */
    auto   int save_len = len;         /* save length at start of input line */

    while( len > 0 )
    {
        if( space == 0 )    /* line buffer is full */
        {
            /*
            ** Line too long.  Start a new line.
            */
            *line = 0;   /* force null terminator */

	    if ( debugging )
	    {
		fputs("Line buffer full:\n", stderr);
		fprintf(stderr, "\tLine: %s\n", line);
	    }

            Syslog( LOG_INFO, "%s", line_buff );
            line  = line_buff;
            space = sizeof(line_buff)-1;
            parse_state = PARSING_TEXT;
	    symbols_expanded = 0;
	    skip_symbol_lookup = 0;
	    save_ptr = ptr;
	    save_len = len;
        }

        switch( parse_state )
        {
        case PARSING_TEXT:
               delta = copyin( line, space, ptr, len, "\n[" );
               line  += delta;
               ptr   += delta;
               space -= delta;
               len   -= delta;

               if( space == 0 || len == 0 )
               {
		  break;  /* full line_buff or end of input buffer */
               }

               if( *ptr == '\0' )  /* zero byte */
               {
                  ptr++;	/* skip zero byte */
                  space -= 1;
                  len   -= 1;

		  break;
	       }

               if( *ptr == '\n' )  /* newline */
               {
                  ptr++;	/* skip newline */
                  space -= 1;
                  len   -= 1;

                  *line = 0;  /* force null terminator */
	          Syslog( LOG_INFO, "%s", line_buff );
                  line  = line_buff;
                  space = sizeof(line_buff)-1;
		  if (symbols_twice) {
		      if (symbols_expanded) {
			  /* reprint this line without symbol lookup */
			  symbols_expanded = 0;
			  skip_symbol_lookup = 1;
			  ptr = save_ptr;
			  len = save_len;
		      }
		      else
		      {
			  skip_symbol_lookup = 0;
			  save_ptr = ptr;
			  save_len = len;
		      }
		  }
                  break;
               }
               if( *ptr == '[' )   /* possible kernel symbol */
               {
                  *line++ = *ptr++;
                  space -= 1;
                  len   -= 1;
	          if (!skip_symbol_lookup)
                     parse_state = PARSING_SYMSTART;      /* at < */
                  break;
               }
               break;
        
        case PARSING_SYMSTART:
               if( *ptr != '<' )
               {
                  parse_state = PARSING_TEXT;        /* not a symbol */
                  break;
               }

               /*
               ** Save this character for now.  If this turns out to
               ** be a valid symbol, this char will be replaced later.
               ** If not, we'll just leave it there.
               */

               sym_start = line; /* this will point at the '<' */

               *line++ = *ptr++;
               space -= 1;
               len   -= 1;
               parse_state = PARSING_SYMBOL;     /* symbol... */
               break;

        case PARSING_SYMBOL:
               delta = copyin( line, space, ptr, len, ">\n[" );
               line  += delta;
               ptr   += delta;
               space -= delta;
               len   -= delta;
               if( space == 0 || len == 0 )
               {
                  break;  /* full line_buff or end of input buffer */
               }
               if( *ptr != '>' )
               {
                  parse_state = PARSING_TEXT;
                  break;
               }

               *line++ = *ptr++;  /* copy the '>' */
               space -= 1;
               len   -= 1;

               parse_state = PARSING_SYMEND;

               break;

        case PARSING_SYMEND:
               if( *ptr != ']' )
               {
                  parse_state = PARSING_TEXT;        /* not a symbol */
                  break;
               }

               /*
               ** It's really a symbol!  Replace address with the
               ** symbol text.
               */
           {
	       auto int sym_space;

	       unsigned long value;
	       auto struct symbol sym;
	       auto char *symbol;

               *(line-1) = 0;    /* null terminate the address string */
               value  = strtoul(sym_start+1, (char **) 0, 16);
               *(line-1) = '>';  /* put back delim */

               if ( !symbol_lookup || (symbol = LookupSymbol(value, &sym)) == (char *)0 )
               {
                  parse_state = PARSING_TEXT;
                  break;
               }

               /*
               ** verify there is room in the line buffer
               */
               sym_space = space + ( line - sym_start );
               if( sym_space < strlen(symbol) + 30 ) /*(30 should be overkill)*/
               {
                  parse_state = PARSING_TEXT;  /* not enough space */
                  break;
               }

               delta = sprintf( sym_start, "%s+0x%x/0x%02x]",
                                symbol, sym.offset, sym.size );

               space = sym_space + delta;
               line  = sym_start + delta;
	       symbols_expanded = 1;
           }
               ptr++;
               len--;
               parse_state = PARSING_TEXT;
               break;

        default: /* Can't get here! */
               parse_state = PARSING_TEXT;

        }
    }

    return;
}


static void LogKernelLine(void)
{
	auto int rdcnt;

	/*
	 * Zero-fill the log buffer.  This should cure a multitude of
	 * problems with klogd logging the tail end of the message buffer
	 * which will contain old messages.  Then read the kernel log
	 * messages into this fresh buffer.
	 */
	memset(log_buffer, '\0', sizeof(log_buffer));
	if ( (rdcnt = ksyslog(2, log_buffer, sizeof(log_buffer)-1)) < 0 )
	{
		if ( errno == EINTR )
			return;
		fprintf(stderr, "klogd: Error return from sys_sycall: " \
			"%d - %s\n", errno, strerror(errno));
	}
	else
		LogLine(log_buffer, rdcnt);
	return;
}


static void LogProcLine(void)
{
	auto int rdcnt;

	/*
	 * Zero-fill the log buffer.  This should cure a multitude of
	 * problems with klogd logging the tail end of the message buffer
	 * which will contain old messages.  Then read the kernel messages
	 * from the message pseudo-file into this fresh buffer.
	 */
	memset(log_buffer, '\0', sizeof(log_buffer));
	if ( (rdcnt = read(kmsg, log_buffer, sizeof(log_buffer)-1)) < 0 )
	{
		int saved_errno = errno;

		if ( errno == EINTR )
			return;
		Syslog(LOG_ERR, "Cannot read proc file system: %d - %s.", \
		       errno, strerror(errno));
		if ( saved_errno == EPERM )
			Terminate();
	}
	else
		LogLine(log_buffer, rdcnt);

	return;
}


static int drop_root(void)
{
	struct passwd *pw;

	if (!(pw = getpwnam(server_user))) return -1;

	if (!pw->pw_uid) return -1;

	if (chroot_dir) {
		if (chdir(chroot_dir)) return -1;
		if (chroot(".")) return -1;
	}

	if (setgroups(0, NULL)) return -1;
	if (setgid(pw->pw_gid)) return -1;
	if (setuid(pw->pw_uid)) return -1;

	return 0;
}


int main(int argc, char *argv[])
{
	auto int	ch,
			use_output = 0;

	auto char	*log_level = (char *) 0,
			*output = (char *) 0;

	pid_t ppid = getpid();
	if (chdir ("/") < 0) {
		fprintf(stderr, "klogd: chdir to / failed: %m");
		exit(1);
	}

	/* Parse the command-line. */
	while ((ch = getopt(argc, argv, "c:df:u:j:iIk:nopsvx2")) != EOF)
		switch((char)ch)
		{
		    case '2':		/* Print lines with symbols twice. */
			symbols_twice = 1;
			break;
		    case 'c':		/* Set console message level. */
			log_level = optarg;
			break;
		    case 'd':		/* Activity debug mode. */
			debugging = 1;
			break;
		    case 'f':		/* Define an output file. */
			output = optarg;
			use_output++;
			break;
		    case 'i':		/* Reload module symbols. */
			SignalDaemon(SIGUSR1);
			return(0);
		    case 'I':
			SignalDaemon(SIGUSR2);
			return(0);
		    case 'j':		/* chroot 'j'ail */
			chroot_dir = optarg;
			log_flags |= LOG_NDELAY;
			break;
		    case 'k':		/* Kernel symbol file. */
			symfile = optarg;
			break;
		    case 'n':		/* don't fork */
			no_fork++;
			break;
		    case 'o':		/* One-shot mode. */
			one_shot = 1;
			break;
		    case 'p':
			SetParanoiaLevel(1);	/* Load symbols on oops. */
			break;
		    case 's':		/* Use syscall interface. */
			use_syscall = 1;
			break;
		    case 'u':		/* Run as this user */
			server_user = optarg;
			break;
		    case 'v':
			printf("klogd %s.%s\n", VERSION, PATCHLEVEL);
			exit (1);
		    case 'x':
			symbol_lookup = 0;
			break;
		}

	if (chroot_dir && !server_user) {
		fputs("'-j' is only valid with '-u'\n", stderr);
		exit(1);
	}

	/* Set console logging level. */
	if ( log_level != (char *) 0 )
	{
		if ( (strlen(log_level) > 1) || \
		     (strchr("12345678", *log_level) == (char *) 0) )
		{
			fprintf(stderr, "klogd: Invalid console logging "
				"level <%s> specified.\n", log_level);
			return(1);
		}
		console_log_level = *log_level - '0';
	}

	/*
	 * The following code allows klogd to auto-background itself.
	 * What happens is that the program forks and the parent quits.
	 * The child closes all its open file descriptors, and issues a
	 * call to setsid to establish itself as an independent session
	 * immune from control signals.
	 *
	 * fork() is only called if it should run in daemon mode, fork is
	 * not disabled with the command line argument and there's no
	 * such process running.
	 */
	if ( (!one_shot) && (!no_fork) )
	{
		if (!check_pid(PidFile))
		{
			signal (SIGTERM, doexit);
			pid_t pid;
			int fl;

			if ( (fl = open(_PATH_DEVNULL, O_RDWR)) < 0 )
			{
				fprintf(stderr, "klogd: %s: %s\n",
				         _PATH_DEVNULL, strerror(errno));
				exit(1);
			}

			if ( (pid = fork()) == -1 )
			{
				fputs("klogd: fork failed.\n", stderr);
				exit(1);
			} else if ( pid == 0 )
			{
				int num_fds = getdtablesize();

				signal (SIGTERM, SIG_DFL);

				/* This is the child closing its file descriptors. */
				if ( dup2(fl, 0) != 0 ||
				     ((!use_output || strcmp(output, "-")) &&
				      dup2(fl, 1) != 1) ||
				     dup2(fl, 2) != 2)
				{
					fputs("klogd: dup2 failed.\n", stderr);
					exit(1);
				}
				for (fl= 3; fl <= num_fds; ++fl)
					close(fl);

				setsid();
			}
			else
			{
				/*
				 * Parent process
				 */
				sleep(300);
				/*
				 * Not reached unless something major went wrong.
				 */
				exit(1);
			}
		}
		else
		{
			fputs("klogd: Already running.\n", stderr);
			exit(1);
		}
	}


	/* tuck my process id away */
	if (!check_pid(PidFile))
	{
		if (!write_pid(PidFile))
			Terminate();
	}
	else
	{
		fputs("klogd: Already running.\n", stderr);
		Terminate();
	}

	/* Signal setups. */
	for (ch= 1; ch < NSIG; ++ch)
		signal(ch, SIG_IGN);
	signal(SIGINT, stop_daemon);
	signal(SIGKILL, stop_daemon);
	signal(SIGTERM, stop_daemon);
	signal(SIGHUP, stop_daemon);
	signal(SIGTSTP, stop_logging);
	signal(SIGCONT, restart);
	signal(SIGUSR1, reload_daemon);
	signal(SIGUSR2, reload_daemon);


	/* Open outputs. */
	if ( use_output )
	{
		if ( strcmp(output, "-") == 0 )
			output_file = stdout;
		else if ( (output_file = fopen(output, "w")) == (FILE *) 0 )
		{
			fprintf(stderr, "klogd: Cannot open output file " \
				"%s - %s\n", output, strerror(errno));
			return(1);
		}
	}
	else
		openlog("kernel", log_flags, LOG_KERN);


	/* Handle one-shot logging. */
	if ( one_shot )
	{
		if (symbol_lookup) {
			symbol_lookup  = (InitKsyms(symfile) == 1);
			symbol_lookup |= InitMsyms();
			if (symbol_lookup == 0) {
				Syslog(LOG_WARNING, "cannot find any symbols, turning off symbol lookups\n");
			}
		}
		if ( (logsrc = GetKernelLogSrc()) == kernel )
			LogKernelLine();
		else
			LogProcLine();
		Terminate();
	}

	/* Determine where kernel logging information is to come from. */
#if defined(KLOGD_DELAY)
	sleep(KLOGD_DELAY);
#endif
	logsrc = GetKernelLogSrc();
	if (symbol_lookup) {
		symbol_lookup  = (InitKsyms(symfile) == 1);
		symbol_lookup |= InitMsyms();
		if (symbol_lookup == 0) {
			Syslog(LOG_WARNING, "cannot find any symbols, turning off symbol lookups\n");
		}
	}

	if (getpid() != ppid)
		kill (ppid, SIGTERM);

	if (server_user && drop_root()) {
		syslog(LOG_ALERT, "klogd: failed to drop root");
		Terminate();
	}

        /* The main loop. */
	while (1)
	{
		if ( change_state )
			ChangeLogging();
		switch ( logsrc )
		{
			case kernel:
	  			LogKernelLine();
				break;
			case proc:
				LogProcLine();
				break;
		        case none:
				pause();
				break;
		}
	}
}
/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
