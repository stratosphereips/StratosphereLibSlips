# Copyright (c) 2016 Cisco Systems, Inc.

lib_LTLIBRARIES = libslips.la

include_HEADERS = slips.h
libslips_la_SOURCES = markov_chains.cc	processor.cc util.cc \
			markov_models_1.cc slips.cc $(include_HEADERS)
libslips_la_LDFLAGS = -version-info 1:0:0

AM_CXXFLAGS = -fPIC -pthread -g -std=c++11 -Wall

