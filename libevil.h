
#ifndef _LIBEVIL_H
#define _LIBEVIL_H


#define __cons __attribute__((constructor))

#define TRAP(func, params)                                              \
        evil_##func params;                                             \
        static int (*real_##func) params;                               \
        static void set_real_##func (void) __cons;                      \
        static void set_real_##func (void)                              \
        { real_##func = dlsym (RTLD_NEXT, #func); }                     \
        int __REDIRECT (evil_##func, params, func);                     \
        int evil_##func params


enum {
        NO = 0,
        YES = 1
};

#define EPOCH_FILE "/.epoch"
#define LICDIR "/lic"
#define PERMITFILE LICDIR "/permit.asc"

#endif /* !_LIBEVIL_H */
