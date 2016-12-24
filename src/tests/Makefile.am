## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2006 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
-include $(TOP)/global-vars

LIBEC_CFLAGS		= @libec_cflags@
BUILD_LIBEC_LDFLAGS	= @my_ldflags@ @rpath@

if STATIC_COMPILE
testLDFLAGS=$(BUILD_LIBEC_LDFLAGS)
testLDADD=../libec.la 
else
testLDFLAGS=$(BUILD_LIBEC_LDFLAGS)
testLDADD=../libec.la 
endif

SUBDIRS =

EXTRA_DIST = *.h

check_PROGRAMS = \
	test1 

test1_SOURCES = test1.c time_diff.c
test1_LDFLAGS = $(testLDFLAGS)
test1_LDADD   = $(testLDADD)
test1_CFLAGS = -I$(TOP) $(LIBEC_CFLAGS)

