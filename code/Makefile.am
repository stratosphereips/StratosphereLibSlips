# Copyright (c) 2016 Cisco Systems, Inc.

bin_PROGRAMS = slips

slips_SOURCES = testslips.cc
slips_CPPFLAGS = -I$(top_srcdir)/src
slips_LDADD = $(top_builddir)/src/libslips.la
slips_DEPENCENCIES = $(slips_LDADD)

EXTRA_DIST = models netflows slips.conf

if DEBUG
    AM_CXXFLAGS = -DDEBUG -fPIC -pthread -g -std=c++11
else
    AM_CXXFLAGS = -pthread -fPIC -g -std=c++11
endif
