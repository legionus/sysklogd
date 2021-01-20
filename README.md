# Kernel and system logging daemons

This package is a collection of logging daemons.

* `syslogd` - this daemon is an enhanced version of the standard Berkeley
  utility program. This daemon is responsible for providing logging of messages
  received from programs and facilities on the local host as well as from remote
  hosts.

* `klogd` - listens to kernel message sources and is responsible for
  prioritizing and processing operating system messages. The klogd daemon can
  run as a client of syslogd or optionally as a standalone program.

Original placement: https://www.infodrom.org/projects/sysklogd

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
