#!/bin/sh -efu

priorities='emerg alert crit err warning notice info debug panic error warn'

facilities='auth authpriv cron daemon kern lpr mail news security syslog user
uucp local0 local1 local2 local3 local4 local5 local6 local7'

prepare()
{
	local suffix=''
	[ "$#" -eq 1 ] || suffix="$2"
	rm -rf -- "$1/output${suffix}"
	mkdir -p -- \
		"$1/output${suffix}" \
		"$1/syslog${suffix}.d"
	:>"$1/syslog-mark${suffix}.log"

	hostname example.org
}

run_syslogd()
{
	local suffix=''
	if [ "$#" -gt 0 ]; then
		suffix="$1"
		shift
	fi

	local syslogd

	#syslogd=/sbin/syslogd
	syslogd="$top_builddir/src/syslogd/syslogd"

	${SYSLOGD_WRAPPER-} \
	"$syslogd" -n -ddd \
		-m 1 \
		-p "$WORKDIR/log${suffix}" \
		-P "$WORKDIR/syslog${suffix}.d" \
		-f "$WORKDIR/syslog${suffix}.conf" \
		"$@" \
		>"$WORKDIR/syslogd${suffix}.log" 2>&1 &
	SYSLOGD_PID="$!"

	local i=100 rc=1
	while [ "$i" -gt 0 ]; do
		if grep -qsi -e 'opened UNIX socket ' "$WORKDIR/syslogd${suffix}.log"; then
			rc=0
			break
		fi
		i=$(($i - 1))
		sleep 0.3
	done
	return $rc
}

wait_mark()
{
	local suffix=''
	[ "$#" -eq 0 ] || suffix="$1"

	logger --socket "$WORKDIR/log${suffix}" -p "user.info" -- "-- MARK --"

	local i=100 rc=1
	while [ "$i" -gt 0 ]; do
		if grep -qs -F -e '-- MARK --' "$WORKDIR/syslog-mark${suffix}.log"; then
			rc=0
			break
		fi
		i=$(($i - 1))
		sleep 0.3
	done
	return $rc
}

normilize_logs()
{
	(set +f; sed -r -i -f "$srcdir/filter.sed" "$1"/*.log)
}
