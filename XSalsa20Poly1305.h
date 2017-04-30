#include <string.h>
#include <stdlib.h>
#ifdef HAVE_STDINT
    #include <stdint.h>
#else
    #ifdef HAVE_INTTYPES
        #include <inttypes.h>
    #endif
#endif

#define ZeroMemory(dest,count) memset((void *)dest, 0, count)

int decrypt_string_xs(const char *key, const char *str, char *dest, int len);
int encrypt_string_xs(const char *key, const char *str, char *dest, int len);
