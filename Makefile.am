ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS =
AM_CFLAGS   =
AM_CXXFLAGS =
AM_LDFLAGS  =

AM_CPPFLAGS += $(HTTPLIB_CFLAGS)
AM_LDFLAGS  += $(HTTPLIB_LIBS)

AM_CPPFLAGS += $(SSL_CFLAGS)
AM_LDFLAGS  += $(SSL_LIBS)

check_PROGRAMS =

check_PROGRAMS += test-ranges
test_ranges_SOURCES = tests/test-ranges.cc

check_PROGRAMS += test-ranges2
test_ranges2_SOURCES = tests/test-ranges2.cc

TESTS = $(check_PROGRAMS)
