#ifndef _MD5_H
#define _MD5_H

#include <stdint.h>

int libevil_md5sum_file (int dirfd, const char *path, uint8_t *out);
void libevil_md5sum_fd (int fd, uint8_t *out);

#endif /* ! _MD5_H */
