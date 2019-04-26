/* this header file consist of security manager data structure
main role of this module is to maintain SSL/RSA/AES key management 
Roles are as follows 
*/


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DEV_RSA_C)

#include "mbedtls/rsa.h"
#include "mbedtls/rsa_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#include &lt;string.h&gt;

#if defined(MBEDTLS_PKCS1_V21)
#include "mbedtls/md.h"
#endif

#if defined(MBEDTLS_PKCS1_V15) && !defined(__OpenBSD__)
#include &lt;stdlib.h&gt;
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include &lt;stdio.h&gt;
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

int verbose=1;

#include "mbedtls/sha1.h"
/*
 * Example RSA-1024 keypair, for test purposes
 */

#define PLAIN_TEXT_MAX_LEN  24
#define RSA_CIPHERD_LEN 128


typedef struct security_mgr
{
	 //RSA cloud PUBLIC KEY
	 //RSA device  PRVT KEY
	mbedtls_rsa_context *t_device_dsa;
	mbedtls_rsa_context *t_cloud_dsa;

}security_mgr_t;