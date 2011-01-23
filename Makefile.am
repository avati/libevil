EXTRA_DIST = autogen.sh COPYING INSTALL libevil.spec

libevil_LTLIBRARIES = libevil.la
libevildir = /opt/libevil
noinst_HEADERS = libevil.h
libevil_la_SOURCES = libevil.c
libevil_la_CFLAGS = -D_GNU_SOURCE -fPIC -Wall -pthread -shared -nostartfiles
libevil_la_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
libevil_la_LDFLAGS = -module -avoidversion
# libevil_la_LIBADD =

CLEANFILES =
