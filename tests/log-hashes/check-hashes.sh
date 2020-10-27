#!/bin/sh -efu

logfile="$1"

empty_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

lineno=1
prevhash="$empty_hash"
prevline=
while read -r logline; do
	loghash="${logline%% *}"
	msg="${logline#$loghash }"

	hash="sha256:$(printf '%s %s\n' "$prevhash" "$msg" |sha256sum)" ||:
	hash="${hash%% *}"

	if [ "$hash" != "$loghash" ]; then
		printf >&2 'ERROR: hash chain broken at lineno=%d\n' "$lineno"
		printf >&2 'expected hash: %s\n' "$hash"
		printf >&2 '  logged hash: %s\n' "$loghash"
		exit 1
	fi

	prevhash="$loghash"
	prevline="$logline"

	lineno=$(($lineno + 1))
done < "$logfile"
