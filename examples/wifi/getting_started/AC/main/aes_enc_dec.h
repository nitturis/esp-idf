#define _POSIX_C_SOURCE 1

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#if !defined(_WIN32_WCE)
#include <io.h>
#endif
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

typedef struct aes_enc_dec_s{
    mbedtls_aes_context aes_ctx;    
    mbedtls_md_context_t sha_ctx;

    int mode;
#ifdef TEST_MODE    
   
    unsigned char plain_buffer[4096];
    unsigned char *enc_buffer[4096];
#else
    unsigned char *plain_buffer;//[4096];
    unsigned char *enc_buffer;//[4096];
#endif

    size_t plain_len;
    size_t enc_len;

    unsigned char key[32]; //for AES 1024
    size_t keylen;

    unsigned char IV[16];
    unsigned char digest[32];


}aes_t;

int aes_enc_dec(aes_t *aes_encdec_ctx );