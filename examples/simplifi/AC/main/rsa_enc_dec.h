
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"



#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"


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




#endif

typedef struct rsa_s1{
	//test
    mbedtls_pk_context cloud_privk;

    mbedtls_pk_context cloud_pubk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char buf[1024];
} enc_cloud_pk_t;

typedef struct rsa_s2{
	//test
    mbedtls_pk_context dev_pubk;

    mbedtls_pk_context dev_privk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char buf[1024];
} dec_dev_pk_t;

int dev_rsa_priv_key_int( dec_dev_pk_t *pk, unsigned char *pwd);
int dev_rsa_decrypt(dec_dev_pk_t  *pk,
        unsigned char *rsa_ciphertext,size_t cipher_len,
        unsigned char *rsa_decrypted , size_t *decrypt_len);

int dev_rsa_pub_key_init( dec_dev_pk_t *pk );
int dev_rsa_encrypt(dec_dev_pk_t *pk,
        unsigned char *rsa_plaintext, size_t ilen,
        unsigned char *rsa_ciphertext, size_t *olen
        );
    
#if 0
int cloud_rsa_prv_key_init( mbedtls_pk_context *rsa );

int cloud_rsa_decrypt(mbedtls_pk_context *rsa,
        char *rsa_ciphertext,int cipher_len
        char *rsa_decrypted , int decrypt_len);

int cloud_rsa_encrypt(mbedtls_pk_context *rsa,
        char *rsa_plaintext
        char *rsa_ciphertext
        );
#endif