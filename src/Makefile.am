## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2017 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = .
include $(TOP)/global-vars

CRYPTO_SRC_PREFIX = openssl

EXTRA_DIST = \
	tests

if LIBEC_ENABLE_IPHONE
TOOLS_AND_TESTS =
else
TOOLS_AND_TESTS = tests
endif

SUBDIRS = $(TOOLS_AND_TESTS)

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/include \
	$(COND_INCLUDES)
 
nobase_include_HEADERS = \
	libec/*.h

SRCS = \
	libec.c

lib_LTLIBRARIES = libec.la

libec_la_SOURCES = $(SRCS)

libec_la_LDFLAGS = \
	$(BUILD_LIBEC_LDFLAGS) \
	-version-number "$(PACKAGE_VERSION)" \
	-version-info "$(INTERFACE_CURRENT):$(INTERFACE_REVISION):$(INTERFACE_AGE)"

libec_la_CFLAGS   = $(BUILD_LIBEC_CFLAGS) $(SYSTEM_CFLAGS)

libec_la_LIBADD   = $(BUILD_LIBEC_LDADD)

bin_SCRIPTS = scripts/libec-config

