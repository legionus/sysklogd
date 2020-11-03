#!/bin/sh -efu

priorities='emerg alert crit err warning notice info debug panic error warn'

facilities='auth authpriv cron daemon kern lpr mail news security syslog user
uucp local0 local1 local2 local3 local4 local5 local6 local7'

prepare()
{
	rm -rf -- "$WORKDIR/output"

	mkdir -p -- \
		"$WORKDIR/expect" \
		"$WORKDIR/output" \
		"$WORKDIR/syslog.d"

	:>"$WORKDIR/syslog-mark.log"
}

run_syslogd()
{
	"$TOPDIR/syslogd" -n -d \
		-m 1 \
		-p "$WORKDIR/log" \
		-P "$WORKDIR/syslog.d" \
		-f "$WORKDIR/syslog.conf" \
		"$@" \
		>"$WORKDIR/syslogd.log" 2>&1
}

wait_mark()
{
	logger --socket "$WORKDIR/log" -p "user.info" -- "-- MARK --"
	local c=0
	while [ "$c" -lt 1 ]; do
		c="$(grep -c -F -e '-- MARK --' "$WORKDIR/syslog-mark.log")" ||:
	done
}

normilize_logs()
{
	(set +f; sed -r -i -f "$TOPDIR/tests/filter.sed" "$1"/*.log)
}
