#!/bin/sed

# Date
s/^(Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Oct(ober)?|Nov(ember)?|Dec(ember)?) +/May /
s/^(May) [0-9]{1,2} /\1 1 /
s/^(May 1) [0-9]{2}:[0-9]{2}:[0-9]{2} /\1 12:34:56 /

# Hostname
s/^(May 1 12:34:56) [^[:space:]]+ /\1 example.com /

# Username
s/^(May 1 12:34:56 example.com) [^[:space:]]+: /\1 user: /

# Syslog version
s/^(May 1 12:34:56 example.com syslogd) [0-9]+.[0-9]+.[0-9]+: (restart.*\.)/\1 1.6.0: \2/

/-- MARK --/d
