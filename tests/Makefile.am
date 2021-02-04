LOG_DRIVER = env \
	     "srcdir=$(abs_srcdir)" \
	     "top_srcdir=$(abs_top_srcdir)" \
	     "builddir=$(abs_builddir)" \
	     "top_builddir=$(abs_top_builddir)" \
	$(SHELL) $(top_srcdir)/test-driver

TESTS =
TESTS += check-dedup-messages
TESTS += check-dedup-messages-disabled
TESTS += check-facility-splitting
TESTS += check-forward-net
TESTS += check-forward-unixaf
TESTS += check-log-hashes
TESTS += check-long-messages
TESTS += check-named-pipes
TESTS += check-priority-exclamation
TESTS += check-priority-exclusion
TESTS += check-priority-splitting
TESTS += check-memory-leak

EXTRA_DIST = common.sh filter.sed data verify-hashes.sh $(TESTS)

clean-local:
	rm -rf -- $(abs_builddir)/_build
