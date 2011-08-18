/*
   Copyright (c) 2011 Gluster, Inc. <http://www.gluster.com>
   This file is part of GlusterFS.

   GlusterFS is free software; you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation; either version 3 of the License,
   or (at your option) any later version.

   GlusterFS is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see
   <http://www.gnu.org/licenses/>.
*/

#include <dlfcn.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <utime.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <ctype.h>
#include <sys/ptrace.h>


#include "libevil.h"
#include "md5.c"


static const char *protpatterns[] =  {
        EPOCH_FILE,
        DEFAULT_FILE,
        LICDIR,
        LICDIR "/gpgv",
        LICDIR "/pubring.gpg",
        "/etc",
        "/etc/ld.*.preload",
        "/lib*",
        "/lib*/libevil*.so",
        NULL,
};


static const char *licensed_symbols[] = {
        "iobuf_get",
        "gf_log_init",
        NULL,
};


static int le_debug = 0;
static long int default_timeout = 0;


static int
dbg (const char *fmt, ...)
{
        int     ret = 0;
        va_list ap;

        if (!le_debug)
                return 0;

        va_start (ap, fmt);
        ret = vfprintf (stderr, fmt, ap);
        va_end (ap);

        return ret;
}


static int
err (const char *fmt, ...)
{
        int     ret = 0;
        va_list ap;

        va_start (ap, fmt);
        ret = vfprintf (stderr, fmt, ap);
        va_end (ap);

        return ret;
}


static char *
strip_n (char *str)
{
        char *n = NULL;

        n = strchr (str, '\n');
        if (n)
                *n = '\0';

        return str;
}


static void
dbg_init ()
{
        if (getenv ("LE_DEBUG"))
                le_debug = 1;
}


static int
globerr (const char *epath, int eerrno)
{
        dbg ("%s: %s\n", epath, strerror (eerrno));

        return 0;
}


struct permit_entry {
        struct permit_entry *next;
        unsigned char        md5sum[16];
        char                *path;
};


static struct {
        pthread_rwlock_t     rwlock;
        glob_t               protglob;
        struct stat         *stats;
        int                  permitcnt;
        struct permit_entry *permits;
        char                 macid[64];
        pthread_t            bigbro;
} protect;


static int is_signed_file (const char *filename);

static void
__rehash_glob (void)
{
        int          ret = 0;
        int          i = 0;
        int          globflags = GLOB_BRACE;
        const char  *pattern = NULL;
        char       **files = NULL;
        struct stat *stats = NULL;


        if (protect.protglob.gl_pathc) {
                globfree (&protect.protglob);
                protect.protglob.gl_pathc = 0;
                if (protect.stats)
                        free (protect.stats);
                protect.stats = NULL;
        }

        for (i = 0; (pattern = protpatterns[i]); i++) {
                ret = glob (pattern, globflags, globerr, &protect.protglob);

                if (ret && ret != GLOB_NOMATCH) {
                        globfree (&protect.protglob);
                        protect.protglob.gl_pathc = 0;
                        return;
                }

                globflags |= GLOB_APPEND;
        }

        files = protect.protglob.gl_pathv;

        stats = calloc (protect.protglob.gl_pathc, sizeof (*stats));
        if (!stats) {
                globfree (&protect.protglob);
                protect.protglob.gl_pathc = 0;
                return;
        }

        for (i = 0; i < protect.protglob.gl_pathc; i++) {
                ret = lstat (files[i], &stats[i]);
                if (ret == 0) {
#if 0
                        dbg ("%s: %lld/%lld\n", files[i],
                             (long long) (stats[i].st_ino),
                             (long long) (stats[i].st_dev));
#endif
                } else {
                        dbg ("%s: %s\n", files[i], strerror (errno));
                }
        }

        protect.stats = stats;

        return;
}


static void
rehash_glob (void)
{
        pthread_rwlock_wrlock (&protect.rwlock);
        {
                __rehash_glob ();
        }
        pthread_rwlock_unlock (&protect.rwlock);
}


static void
prepare_glob (void)
{
        pthread_rwlock_init (&protect.rwlock, NULL);
        rehash_glob ();
}


static int
__is_protected_atpath (int dirfd, const char *path, int follow)
{
        int           i = 0;
        int           pathc = 0;
        struct stat  *stats = NULL;
        struct stat   mystat = {0, };
        int           ret = 0;
        int           flags = AT_SYMLINK_NOFOLLOW;

        pathc = protect.protglob.gl_pathc;
        stats = protect.stats;

        if (follow)
                flags = 0;

        ret = fstatat (dirfd, path, &mystat, flags);
        if (ret)
                return NO;

        for (i = 0; i < pathc; i++) {
                if (stats[i].st_ino == mystat.st_ino
                    && stats[i].st_dev == mystat.st_dev)
                        return YES;
        }

        return NO;
}


static int
__is_protected_atfile (int dirfd, const char *path)
{
        return __is_protected_atpath (dirfd, path, 1);
}


static int
is_protected_atfile (int dirfd, const char *path)
{
        int   ret = 0;

        pthread_rwlock_rdlock (&protect.rwlock);
        {
                ret = __is_protected_atfile (dirfd, path);
        }
        pthread_rwlock_unlock (&protect.rwlock);

        return ret;
}


static int
__is_protected_atentry (int dirfd, const char *path)
{
        return __is_protected_atpath (dirfd, path, 0);
}


static int
is_protected_atentry (int dirfd, const char *path)
{
        int   ret = 0;

        pthread_rwlock_rdlock (&protect.rwlock);
        {
                ret = __is_protected_atentry (dirfd, path);
        }
        pthread_rwlock_unlock (&protect.rwlock);

        return ret;
}


static int
is_protected_file (const char *path)
{
        int   ret = 0;

        pthread_rwlock_rdlock (&protect.rwlock);
        {
                ret = __is_protected_atfile (AT_FDCWD, path);
        }
        pthread_rwlock_unlock (&protect.rwlock);

        return ret;
}


static int
is_protected_entry (const char *path)
{
        int   ret = 0;

        pthread_rwlock_rdlock (&protect.rwlock);
        {
                ret = __is_protected_atentry (AT_FDCWD, path);
        }
        pthread_rwlock_unlock (&protect.rwlock);

        return ret;
}


static int
__is_protected_fd (int fd)
{
        int           i = 0;
        int           pathc = 0;
        struct stat  *stats = NULL;
        struct stat   mystat = {0, };
        int           ret = 0;

        pathc = protect.protglob.gl_pathc;
        stats = protect.stats;

        ret = fstat (fd, &mystat);
        if (ret)
                return NO;

        for (i = 0; i < pathc; i++) {
                if (stats[i].st_ino == mystat.st_ino
                    && stats[i].st_dev == mystat.st_dev)
                        return YES;
        }

        return NO;
}


static int
is_protected_fd (int fd)
{
        int   ret = 0;

        pthread_rwlock_rdlock (&protect.rwlock);
        {
                ret = __is_protected_fd (fd);
        }
        pthread_rwlock_unlock (&protect.rwlock);

        return ret;
}


static time_t
get_default_deadline (void)
{
        struct stat epoch_stat = {0, };
        int         ret = 0;
        time_t      epoch = 0;

        ret = lstat (EPOCH_FILE, &epoch_stat);
        if (ret != 0)
                return 0;

        epoch = epoch_stat.st_ctime;
        if (epoch_stat.st_mtime < epoch)
                epoch = epoch_stat.st_mtime;
        if (epoch_stat.st_atime < epoch)
                epoch = epoch_stat.st_atime;

        return (epoch + default_timeout);
}


static time_t
license_parse (FILE *fp)
{
        char   line[1024];
        char  *l = NULL;
        char  *saveptr = NULL;;
        char  *macid = NULL;
        char  *timestamp = NULL;
        char  *end = NULL;
        time_t final_ts = 0;
        time_t ts = 0;
        char   timebuf[64];


        while ((l = fgets (line, 1024, fp))) {
                macid = strtok_r (line, " \r\n\t", &saveptr);
                if (!macid)
                        continue;

                if (strcmp (macid, protect.macid) != 0) {
                        macid = NULL;
                        continue;
                }

                dbg ("found entry macid=%s\n", macid);

                timestamp = strtok_r (NULL, " \r\n\t", &saveptr);
                if (!timestamp) {
                        macid = NULL;
                        continue;
                }

                dbg ("found timestamp %s for macid=%s\n", timestamp, macid);
                ts = strtoul (timestamp, &end, 10);
                if (*end != '\0') {
                        macid = NULL;
                        timestamp = NULL;
                        continue;
                }

                if (ts > final_ts)
                        final_ts = ts;
        }

        dbg ("final timestamp = %llu (%s)\n", (unsigned long long) final_ts,
             strip_n (ctime_r (&final_ts, timebuf)));

        return final_ts;
}


static time_t
get_license_deadline (void)
{
        int                  ret = 0;
        struct stat          lic_stat = {0, };
        static struct stat   lic_stat_prev = {0, };
        static time_t        lic_deadline = 0;
        FILE                *lfp = NULL;

        /* be symlink friendly */
        ret = stat (LICFILE, &lic_stat);
        if (ret)
                return 0;

        if (lic_stat.st_mtime == lic_stat_prev.st_mtime &&
            lic_stat.st_ctime == lic_stat_prev.st_ctime &&
            lic_stat.st_ino   == lic_stat_prev.st_ino &&
            lic_stat.st_dev   == lic_stat_prev.st_dev) {
                /* nothing changed */
                return lic_deadline;
        }

        lfp = fopen (LICFILE, "r");
        if (!lfp)
                return 0;

        ret = is_signed_file (LICFILE);
        if (ret != YES) {
                fclose (lfp);
                return 0;
        }

        lic_deadline = license_parse (lfp);
        lic_stat_prev = lic_stat;

        fclose (lfp);

        return lic_deadline;
}


static time_t
get_latest_deadline (void)
{
        time_t              def_deadline = 0;
        time_t              lic_deadline = 0;
        time_t              deadline = 0;
        char                timebuf1[64];
        char                timebuf2[64];

        def_deadline = get_default_deadline ();
        lic_deadline = get_license_deadline ();

        dbg ("def_deadline = %s lic_deadline=%s\n",
             strip_n (ctime_r (&def_deadline, timebuf1)),
             strip_n (ctime_r (&lic_deadline, timebuf2)));

        deadline = MAX (def_deadline, lic_deadline);

        return deadline;
}


static void *
bigbro_is_watching (void *data)
{
        int     can_live = YES;
        time_t  deadline = -1;
        time_t  new_deadline = 0;
        time_t  now = 0;
        char    timebuf1[64];
        char    timebuf2[64];

        for (can_live = YES; can_live == YES; sleep (10)) {
                new_deadline = get_latest_deadline ();
                if (deadline != new_deadline) {
                        dbg ("updated deadline: %s\n",
                             strip_n (ctime_r (&new_deadline, timebuf1)));
                }
                deadline = new_deadline;
                now = time (NULL);

                if (deadline < now) {
                        err ("deadline was: %s, now is: %s\n",
                             strip_n (ctime_r (&deadline, timebuf1)),
                             strip_n (ctime_r (&now, timebuf2)));
                        /* >:) */
                        break;
                }
        }

        exit (1);

        return NULL;
}


static void
bb_child (void)
{
        int ret = 0;

        ret = pthread_create (&protect.bigbro, NULL, bigbro_is_watching, NULL);
        if (ret != 0)
                protect.bigbro = 0;
}


static void
big_brother_kickoff (void)
{
        int ret = 0;

        ret = pthread_atfork (NULL, NULL, bb_child);
        if (ret != 0) {
                dbg ("failed pthread_atfork (%s)\n", strerror (errno));
                return;
        }

        ret = pthread_create (&protect.bigbro, NULL, bigbro_is_watching, NULL);
        if (ret != 0)
                protect.bigbro = 0;
}


static int  is_licensed = -1;


static int
is_licensed_prog (void)
{
        int         i = 0;
        const char *symbol = NULL;


        if (is_licensed == -1) {
                for (i = 0; (symbol = licensed_symbols[i]); i++) {
                        if (dlsym (RTLD_NEXT, symbol) != NULL) {
                                is_licensed = 1;
                                break;
                        }
                }

                if (!symbol)
                        is_licensed = 0;

                if (is_licensed) {
                        dbg ("found symbol %s -- is a licensed program\n",
                             symbol);
                        big_brother_kickoff ();
                }
        }

        return is_licensed;
}


static void
make_licensed_prog (void)
{
        if (is_licensed == 1)
                return;

        is_licensed = 1;
        big_brother_kickoff ();
}


static int
is_signed_file (const char *filename)
{
        int  len = 0;
        int  ret = 0;
        int  status = 0;
        char cmdbuf[1024];

        len = snprintf (cmdbuf, 1024, "%s/gpgv --keyring %s/pubring.gpg %s >/dev/null 2>&1",
                        LICDIR, LICDIR, filename);

        if (len >= 1024) {
                dbg ("cmd too long (%d)\n", len);
                return NO;
        }

        status = system (cmdbuf);

        ret = WEXITSTATUS(status);

        dbg ("%s: %d\n", cmdbuf, status);

        if (ret == 0)
                return YES;

        return NO;
}


static int
__line_has_md5str (const char *line)
{
        int i = 0;
        int ch = 0;

        for (i = 0; i < 32; i++) {
                ch = line[i];
                if (!isxdigit (ch))
                        return NO;
        }

        ch = line[i];
        if (!isspace (ch))
                return NO;

        for (ch = line[i]; (ch = line[i]) && (isspace (ch)); i++);

        for (ch = line[i]; (ch = line[i]); i++)
                if (!isascii (ch))
                        return NO;

        return YES;
}


static int
xnum (char ch)
{
        int n = 0;

        if (isdigit (ch))
                n = (ch - '0');
        if (ch >= 'a' && ch <= 'f')
                n = (ch - 'a' + 10);
        if (ch >= 'A' && ch <= 'F')
                n = (ch - 'A' + 10);

        return n;
}


static void
md5str_to_md5sum (const char *str, unsigned char *sum)
{
        int  i = 0;
        int  j = 0;
        int  ch = 0;

        for (i = 0; i < 32; i++) {
                if (!(i % 2)) {
                        ch = xnum (str[i]);
                        continue;
                }
                ch <<= 4;
                ch += xnum (str[i]);

                sum[j] = ch;
                j++;
        }
}



static int
permits_parse (FILE *fp)
{
        struct permit_entry *entry = NULL;
        struct permit_entry *next = NULL;
        struct permit_entry *head = NULL;
        char                 line[1024];
        char                *l = NULL;

        while ((l = fgets (line, 1024, fp))) {
                if (strlen (l) < 35)
                        continue;
                if (__line_has_md5str (l) != YES)
                        continue;

                entry = calloc (1, sizeof (*entry));
                if (!entry)
                        goto err;
                entry->next = head;
                head = entry;

                md5str_to_md5sum (l, entry->md5sum);

                for (l = &line[32]; *l; l++)
                        if (!isspace (*l))
                                break;
                if (!(*l))
                        goto err;

                entry->path = strdup (l);
                if (!entry->path)
                        goto err;

                l = strchr (entry->path, '\n');
                if (l)
                        *l = '\0';

                l = strchr (entry->path, '\r');
                if (l)
                        *l = '\0';
        }

        protect.permits = head;

        return YES;
err:

        for (entry = head; entry; entry = next) {
                next = entry->next;
                if (entry->path)
                        free (entry->path);
                free (entry);
        }

        return NO;
}


static int
permits_load (void)
{
        const char *permitfile = NULL;
        FILE       *permitfp = NULL;
        struct stat stbuf;
        int         ret = 0;


        if (protect.permits)
                return YES;

        permitfile = getenv ("LE_PERMIT");
        if (!permitfile)
                permitfile = PERMITFILE;

        ret = stat (permitfile, &stbuf);
        /* don't care if it is symlink */
        if (ret != 0) {
                dbg ("%s: %s\n", permitfile, strerror (errno));
                return NO;
        }

        if (!S_ISREG (stbuf.st_mode)) {
                dbg ("%s: Not a regular file\n", permitfile);
                return NO;
        }

        permitfp = fopen (permitfile, "r");
        if (!permitfp) {
                dbg ("%s: %s\n", permitfile, strerror (errno));
                return NO;
        }

        ret = is_signed_file (permitfile);
        /* TODO: provide is_signed_fd which uses is_signed_file with
           /proc/getpid()/fd/%d as filename
        */
        if (ret != YES) {
                dbg ("%s: signature check failed\n", permitfile);
                fclose (permitfp);
                return NO;
        }

        ret = permits_parse (permitfp);
        fclose (permitfp);

        return ret;
}


const char *
get_permitted_path (unsigned char md5sum[16])
{
        struct  permit_entry *entry = NULL;

        for (entry = protect.permits; entry; entry = entry->next) {
                if (memcmp (md5sum, entry->md5sum, 16) == 0)
                        return entry->path;
        }

        return NULL;
}


static int
is_permitted_renameat (int olddirfd, const char *oldpath,
                       int newdirfd, const char *newpath)
{
        struct stat     attempted_dst_stat = {0,};
        struct stat     permitted_dst_stat = {0,};
        struct stat     src_stat = {0, };
        int             ret = 0;
        unsigned char   md5sum[16];
        const char     *permitted_path = NULL;


        ret = fstatat (newdirfd, newpath, &attempted_dst_stat,
                       AT_SYMLINK_NOFOLLOW);
        if (ret != 0)
                return NO;

        ret = fstatat (olddirfd, oldpath, &src_stat,
                       AT_SYMLINK_NOFOLLOW);
        if (ret != 0)
                return NO;

        if (!S_ISREG (src_stat.st_mode))
                return NO;

        ret = libevil_md5sum_file (olddirfd, oldpath, md5sum);
        if (ret != 0)
                return NO;

        ret = permits_load ();
        if (ret != YES)
                return NO;

        permitted_path = get_permitted_path (md5sum);
        if (!permitted_path)
                return NO;

        dbg ("permitted: %s\n", permitted_path);

        ret = lstat (permitted_path, &permitted_dst_stat);
        if (ret != 0) {
                dbg ("%s: %s\n", permitted_path, strerror (errno));
                return NO;
        }

        dbg ("cmp p_i=%llu,p_d=%llu a_i=%llu,a_d=%llu\n",
             (unsigned long long) (permitted_dst_stat.st_ino),
             (unsigned long long) (permitted_dst_stat.st_dev),
             (unsigned long long) (attempted_dst_stat.st_ino),
             (unsigned long long) (attempted_dst_stat.st_dev));

        if (permitted_dst_stat.st_ino == attempted_dst_stat.st_ino &&
            permitted_dst_stat.st_dev == attempted_dst_stat.st_dev)
                return YES;

        return NO;
}


static int
is_permitted_rename (const char *oldpath, const char *newpath)
{
        return is_permitted_renameat (AT_FDCWD, oldpath, AT_FDCWD, newpath);
}


int
TRAP (rename, (const char *oldpath, const char *newpath))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_entry (oldpath))
                goto red;

        if (!is_protected_entry (newpath))
                goto green;

        if (!is_permitted_rename (oldpath, newpath))
                goto red;
green:
        ret = real_rename (oldpath, newpath);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (renameat, (int olddirfd, const char *oldpath,
                 int newdirfd, const char *newpath))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_atentry (olddirfd, oldpath))
                goto red;

        if (!is_protected_atentry (newdirfd, newpath))
                goto green;

        if (!is_permitted_renameat (olddirfd, oldpath, newdirfd, newpath))
                goto red;

green:
        ret = real_renameat (olddirfd, oldpath,
                             newdirfd, newpath);
        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (unlink, (const char *pathname))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_entry (pathname))
                goto red;

green:
        ret = real_unlink (pathname);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (unlinkat, (int dirfd, const const char *pathname, int flags))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_atentry (dirfd, pathname))
                goto red;

green:
        ret = real_unlinkat (dirfd, pathname, flags);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (remove, (const char *pathname))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_entry (pathname))
                goto red;

green:
        ret = real_remove (pathname);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (truncate, (const char *path, off_t length))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (path))
                goto red;

green:
        ret = real_truncate (path, length);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (truncate64, (const char *path, off_t length))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (path))
                goto red;

green:
        ret = real_truncate64 (path, length);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (open, (const char *path, int flags, mode_t mode))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (!is_protected_file (path))
                goto green;

        if ((flags & O_ACCMODE) != O_RDONLY)
                goto red;

green:
        ret = real_open (path, flags, mode);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (openat, (int dirfd, const char *path, int flags, mode_t mode))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (!is_protected_atfile (dirfd, path))
                goto green;

        if ((flags & O_ACCMODE) != O_RDONLY)
                goto red;

green:
        ret = real_openat (dirfd, path, flags, mode);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (creat, (const char *path, mode_t mode))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (path))
                goto red;

green:
        ret = real_creat (path, mode);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (chmod, (const char *path, mode_t mode))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (path))
                goto red;

green:
        ret = real_chmod (path, mode);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (fchmod, (int fd, mode_t mode))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_fd (fd))
                goto red;

green:
        ret = real_fchmod (fd, mode);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (fchmodat, (int dirfd, const char *path, mode_t mode, int flags))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (flags & AT_SYMLINK_NOFOLLOW) {
                if (is_protected_atentry (dirfd, path))
                        goto red;
        } else {
                if (is_protected_atfile (dirfd, path))
                        goto red;
        }

green:
        ret = real_fchmodat (dirfd, path, mode, flags);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (chown, (const char *path, uid_t uid, gid_t gid))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (path))
                goto red;

green:
        ret = real_chown (path, uid, gid);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (lchown, (const char *path, uid_t uid, gid_t gid))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_entry (path))
                goto red;

green:
        ret = real_lchown (path, uid, gid);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (fchown, (int fd, uid_t uid, gid_t gid))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_fd (fd))
                goto red;

green:
        ret = real_fchown (fd, uid, gid);

        return ret;

red:
        errno = EPERM;
        return -1;
}


int
TRAP (fchownat, (int dirfd, const char *path, uid_t uid, gid_t gid, int flags))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (flags & AT_SYMLINK_NOFOLLOW) {
                if (is_protected_atentry (dirfd, path))
                        goto red;
        } else {
                if (is_protected_atfile (dirfd, path))
                        goto red;
        }

green:
        ret = real_fchownat (dirfd, path, uid, gid, flags);

        return ret;
red:
        errno = EPERM;
        return -1;
}


int
TRAP (utime, (const char *filename, const struct utimbuf *times))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (filename))
                goto red;

green:
        ret = real_utime (filename, times);

        return ret;
red:
        errno = EPERM;
        return -1;
}


int
TRAP (utimes, (const char *filename, const struct timeval times[2]))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (filename))
                goto red;

green:
        ret = real_utimes (filename, times);

        return ret;
red:
        errno = EPERM;
        return -1;
}


int
TRAP (utimensat, (int dirfd, const char *pathname,
                  const struct timespec times[2], int flags))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (flags & AT_SYMLINK_NOFOLLOW) {
                if (is_protected_atentry (dirfd, pathname))
                        goto red;
        } else {
                if (is_protected_atfile (dirfd, pathname))
                        goto red;
        }
green:
        ret = real_utimensat (dirfd, pathname, times, flags);

        return ret;
red:
        errno = EPERM;
        return -1;
}


int
TRAP (futimesat, (int dirfd, const char *pathname,
                  const struct timeval times[2]))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_atfile (dirfd, pathname))
                goto red;

green:
        ret = real_futimesat (dirfd, pathname, times);

        return ret;
red:
        errno = EPERM;
        return -1;
}


int
TRAP (mount, (const char *source, const char *target,
              const char *filesystemtype, unsigned long mountflags,
              const void *data))
{
        int ret = 0;

        if (is_licensed_prog ())
                goto green;

        if (is_protected_file (target))
                goto red;

        /* no need to check @source for mount --bind since st_ino/st_dev
           are preserved in namespace bind mounts
        */

green:
        ret = real_mount (source, target, filesystemtype, mountflags, data);

        return ret;
red:
        errno = EPERM;
        return -1;
}


int
TRAP (pivot_root, (const char *new_root, const char *old_put))
{
        /* blanket disable */
        errno = EPERM;
        return -1;
#if 0
        int   ret = 0;

        ret = real_pivot_root (new_root, old_put);

        return ret;
#endif
}


int
TRAP (chroot, (const char *path))
{
        int   ret = 0;

        ret = real_chroot (path);

        return ret;
}


int
TRAP (ptrace, (enum __ptrace_request request, pid_t pid,
               void *addr, void *data))
{
        int   ret = 0;

        ret = real_ptrace (request, pid, addr, data);

        return ret;
}


int
TRAP (execve, (const char *filename, const char *argv[], const char *envp[]))
{
        int   ret = 0;

        unsetenv ("LD_PRELOAD");
        ret = real_execve (filename, argv, envp);

        return ret;
}


int
TRAP (epoll_create, (int flags))
{
        int   ret = 0;

        make_licensed_prog ();

        ret = real_epoll_create (flags);

        return ret;
}


int
TRAP (epoll_create1, (int flags))
{
        int   ret = 0;

        make_licensed_prog ();

        ret = real_epoll_create1 (flags);

        return ret;
}


static void
create_epoch (void)
{
        FILE           *ep = NULL;
        FILE           *def = NULL;
        int             ret = 0;
        int             randfd = -1;
        int             i = 0;
        unsigned char   randbytes[16];
        struct stat     stbuf = {0, };


        if (lstat (EPOCH_FILE, &stbuf) == 0 && stbuf.st_size != 0)
                goto read;

        ep = fopen (EPOCH_FILE, "w+");
        if (!ep)
                return;

        randfd = open ("/dev/urandom", O_RDONLY);
        if (randfd == -1)
                randfd = open ("/dev/random", O_RDONLY);

        if (randfd == -1) {
                fclose (ep);
                return;
        }

        ret = read (randfd, randbytes, sizeof (randbytes));
        if (ret != sizeof (randbytes)) {
                fclose (ep);
                close (randfd);
                return;
        }

        for (i = 0; i < 16; i++) {
                fprintf (ep, "%02x", randbytes[i]);
                if (i == 3 || i == 5 || i == 7 || i == 9)
                        fprintf (ep, "-");
        }
        fprintf (ep, "\n");

        fclose (ep);
        close (randfd);

read:
        ep = fopen (EPOCH_FILE, "r");
        ret = fscanf (ep, "%s", protect.macid);
        fclose (ep);

        def = fopen (DEFAULT_FILE, "r");
        if (def) {
                ret = fscanf (def, "%ld", &default_timeout);
                fclose (def);
        }
        if (!default_timeout)
                default_timeout = DAYS(30);
}


static void libevil_init (void) __attribute__((constructor));


static void
libevil_init (void)
{
        dbg_init ();

        create_epoch ();

        prepare_glob ();

        return;
}

