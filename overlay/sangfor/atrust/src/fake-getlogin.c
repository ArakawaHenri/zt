#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Override getlogin_r / getlogin so aTrustAgent binds its local HTTP service
 * under the non-root user named in FAKE_LOGIN instead of refusing root. */
int getlogin_r(char *buf, size_t bufsize) {
    const char *login = getenv("FAKE_LOGIN");
    if (!login)
        return ENXIO;
    size_t len = strlen(login);
    if (len + 1 > bufsize)
        return ERANGE;
    memcpy(buf, login, len + 1);
    return 0;
}

char *getlogin(void) {
    return getenv("FAKE_LOGIN");
}
