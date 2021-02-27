# Kernel and system logging daemons

This package is a collection of logging daemons.

* `syslogd` - this daemon is an enhanced version of the standard Berkeley
  utility program. This daemon is responsible for providing logging of messages
  received from programs and facilities on the local host as well as from remote
  hosts.

* `klogd` - listens to kernel message sources and is responsible for
  prioritizing and processing operating system messages. The klogd daemon can
  run as a client of syslogd or optionally as a standalone program.

## Fork

This fork, unlike other versions, uses modern features of the linux kernel such
as `epoll(2)` or `signalfd(2)`.

If you're looking for more traditional syskogd variants:

* https://www.infodrom.org/projects/sysklogd (the project that was forked)
* https://github.com/troglobit/sysklogd
* https://github.com/openwall/Owl (The project includes a heavily modified version of [sysklogd](https://github.com/openwall/Owl/tree/main/packages/sysklogd))
* https://github.com/openbsd/src ([syslogd](https://github.com/openbsd/src/blob/master/usr.sbin/syslogd/syslogd.c) is part of it);
* https://github.com/guillemj/inetutils ([syslogd](https://github.com/guillemj/inetutils/blob/master/src/syslogd.c) is part of it).

## Requires

You need the following tools to build it:

* c compiler (gcc / clang)
* libc (glibc / musl)
* GNU autoconf
* GNU automake
* GNU make

## Download

Downloading the current source code:

Source for the latest released version, as well as daily snapshots, can always
be downloaded from

  https://github.com/legionus/sysklogd/releases/

You can browse the up to the minute source code:

  https://github.com/legionus/sysklogd

## Bug reporting

Please report all bugs you find in the package directly to authors.
