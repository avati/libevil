/*
  Copyright (c) 2012 Red Hat, Inc. <http://www.redhat.com>

  GlusterFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  GlusterFS is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>


int
clean_remove (const char *filename)
{
        int ret = 0;

        errno = 0;
        ret = remove (filename);
        if (errno && errno != ENOENT) {
                fprintf (stderr, "remove(%s): %s\n",
                         filename, strerror (errno));
        }

        return ret;
}


int
main (int argc, char *argv[])
{
        const char *entry = NULL;
        int   i = 0;
        const char *remove_entries[] = {
                "/.epoch",
                "/.default",
                "/lic/gpgv",
                "/lic/pubring.gpg",
                "/lic/license.req",
                "/lic/license.asc",
                "/lic",
                "/lib/libevil32.so",
                "/lib64/libevil64.so",
                "/etc/ld.so.preload",
                "/etc/ld.32.preload",
                "/etc/profile.d/gluster-lic.sh",
                NULL,
        };

        for (i = 0; (entry = remove_entries[i]); i++) {
                clean_remove (entry);
        }

        return 0;
}
