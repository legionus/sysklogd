#!/bin/bash -efu

ARGS=()

while [ "$#" -gt 0 ]; do
	if [ "$1" = '--' ]; then
		shift
		break
	fi
	ARGS+=("$1")
	shift
done

ulimit "${ARGS[@]}"
exec "$@"
