EXTRA_DIST = autogen.sh COPYING INSTALL libevil.spec

libevil_PROGRAMS = libevil.so
libevildir = $(prefix)/ldpreload

noinst_HEADERS = libevil.h md5.c
libevil_so_SOURCES = libevil.c
libevil_so_CFLAGS = -D_GNU_SOURCE -fPIC -Wall -pthread -shared
libevil_so_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
libevil_so_LDFLAGS = -module -avoidversion -shared -ldl
# libevil_la_LIBADD =

CLEANFILES =
