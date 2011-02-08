EXTRA_DIST = autogen.sh COPYING INSTALL build-static-gpg.sh gluster-lic.spec

bin_SCRIPTS = gluster-lic-request gluster-lic-setup gluster-lic-install gluster-lic-sign gluster-lic-info

etc_profile_d_SCRIPTS = gluster-lic.sh
etc_profile_ddir = /etc/profile.d

libevil_PROGRAMS = libevil.so gpgv
libevildir = $(prefix)/ldpreload

gpgv_SOURCES =
gpgv: $(srcdir)/build-static-gpg.sh
	$(srcdir)/build-static-gpg.sh

noinst_HEADERS = libevil.h md5.c
libevil_so_SOURCES = libevil.c
libevil_so_CFLAGS = -D_GNU_SOURCE -fPIC -Wall -pthread -shared
libevil_so_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
libevil_so_LDFLAGS = -module -avoidversion -shared -ldl
# libevil_la_LIBADD =

CLEANFILES =
