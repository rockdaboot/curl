if USE_EMBEDDED_ARES
AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(top_builddir)/ares         \
              -I$(top_srcdir)/ares           \
              -DSRCDIR=\"$(abs_srcdir)\"
else
AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -DSRCDIR=\"$(abs_srcdir)\"
endif

#CFLAGS += @CURL_CFLAG_EXTRAS@

#AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
LDADD = $(top_builddir)/lib/libcurl.la $(SUPPORTFILES_LIBS)

#LDADD = ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB) $(INET_PTON_LIB) \
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_CRYPTO) $(LIB_GETLOGIN) $(LIB_NANOSLEEP) $(LIB_POLL) \
 $(LIB_POSIX_SPAWN) $(LIB_PTHREAD_SIGMASK) $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) \
 $(LTLIBMULTITHREAD) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@ \
 $(FUZZ_LIBS)

CURL_TESTS = \
 curl_ftp_fuzzer$(EXEEXT)

#if FUZZING
  bin_PROGRAMS = $(CURL_TESTS)
  LDADD += $(LIB_FUZZING_ENGINE)
  AM_LDFLAGS = -no-install -all-static
#else
#  AM_CPPFLAGS += -DTEST_RUN
#  AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
#  TESTS = $(CURL_TESTS)
#  check_PROGRAMS = $(CURL_TESTS)
#  MAIN = main.c fuzzer.h
#endif

curl_ftp_fuzzer_SOURCES = curl_ftp_fuzzer.c $(MAIN)

dist-hook:
	find $(srcdir) -name '*.options' -exec cp -v '{}' $(distdir) ';'
	find $(srcdir) -name '*.dict' -exec cp -v '{}' $(distdir) ';'
#	find $(srcdir) -name '*.in' -exec cp -vr '{}' $(distdir) ';'
	find $(srcdir) -name '*.repro' -exec cp -vr '{}' $(distdir) ';'

clean-local:
	rm -rf *.gc?? *.log lcov
