EXTRA_DIST = autogen.sh COPYING INSTALL build-static-gpg.sh gluster-lic.spec pubring.gpg

bin_SCRIPTS = gluster-lic-request gluster-lic-setup gluster-lic-install gluster-lic-sign gluster-lic-info gluster-lic-register
bin_PROGRAMS = gpgv gluster-lic-uninstall

gluster_lic_uninstall_SOURCES = gluster-lic-uninstall.c
gluster_lic_uninstall_CFLAGS = -static
gluster_lic_uninstall_LDFLAGS = -static

etc_profile_d_SCRIPTS = gluster-lic.sh
etc_profile_ddir = /etc/profile.d

permit_SCRIPTS = permits-create.sh permits-install.sh
permitdir = $(libdir)

sysconf_DATA = pubring.gpg

gpgv_SOURCES =
gpgv: $(srcdir)/build-static-gpg.sh
	$(srcdir)/build-static-gpg.sh

noinst_HEADERS = libevil.h md5.c

le_PROGRAMS = libevil.so
ledir = $(libdir)
libevil_so_SOURCES = libevil.c
libevil_so_CFLAGS = -D_GNU_SOURCE -fPIC -Wall -pthread -shared
libevil_so_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
libevil_so_LDFLAGS = -module -avoidversion -shared -ldl
# libevil_la_LIBADD =

CLEANFILES =
