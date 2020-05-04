Kernel and system logging daemons [![Build Status](https://travis-ci.org/legionus/sysklogd.svg?branch=master)](https://travis-ci.org/legionus/sysklogd)
=================================

This package implements two system log daemons. The syslogd daemon is an
enhanced version of the standard Berkeley utility program. This daemon is
responsible for providing logging of messages received from programs and
facilities on the local host as well as from remote hosts.

The klogd daemon listens to kernel message sources and is responsible for
prioritizing and processing operating system messages. The klogd daemon can run
as a client of syslogd or optionally as a standalone program.

Original placement: https://www.infodrom.org/projects/sysklogd

