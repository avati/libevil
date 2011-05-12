dnl Copyright (c) 2011 Gluster, Inc. <http://www.gluster.com>
dnl This file is part of GlusterFS.
dnl
dnl GlusterFS is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU Affero General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl GlusterFS is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Affero General Public License for more details.
dnl
dnl You should have received a copy of the GNU Affero General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT([gluster-lic],[0.3],[support@gluster.com])

AM_INIT_AUTOMAKE

AC_CONFIG_FILES([Makefile
                gluster-lic-setup
                gluster-lic-request
                gluster-lic-register
                gluster-lic-install
                gluster-lic-sign
                gluster-lic-info
                gluster-lic.spec
                gluster-lic.sh])

AC_CANONICAL_HOST

AC_PROG_CC
#AC_PROG_LIBTOOL

AC_CHECK_TOOL([LD],[ld])

AC_CHECK_LIB([pthread], [pthread_mutex_init], ,AC_MSG_ERROR([Posix threads library is required by libevil]))

AC_CHECK_FUNC([pthread_spin_init], [have_spinlock=yes])
if test "x${have_spinlock}" = "xyes"; then
   AC_DEFINE(HAVE_SPINLOCK, 1, [define if found spinlock])
fi
AC_SUBST(HAVE_SPINLOCK)


AC_OUTPUT
