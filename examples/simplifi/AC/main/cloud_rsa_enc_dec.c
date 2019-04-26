#include "rsa_enc_dec.h"

/*
 * Example RSA-1024 keypair, for test purposes
 */


extern const unsigned char cloud_priv_key_rsa_start[]  asm("_binary_cloud_priv_1024_pem_start");
extern const unsigned char cloud_priv_key_rsa_end[]    asm("_binary_cloud_priv_1024_pem_end");
extern const unsigned char cloud_pub_key_rsa_start[]  asm("_binary_cloud_pub_1024_pem_start");
extern const unsigned char cloud_pub_key_rsa_end[]    asm("_binary_cloud_pub_1024_pem_end");

//static const char *TAG = "RSA-1024";
int verbose=1;


/*
 * Checkup routine
 */
//keep this part of security mgr srtuct
;
//mbedtls_x509_crt cacert;

int cloud_rsa_pub_key_init(  enc_cloud_pk_t *pkt )
{
    //FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
 //   size_t i;//, olen = 0;
  
//    unsigned char input[1024];
    const unsigned char *buf= cloud_pub_key_rsa_start;
    size_t keylen= (size_t)(cloud_pub_key_rsa_end-cloud_pub_key_rsa_start);
    
  //  const char *pers = "mbedtls_pk_encrypt";
    mbedtls_pk_context *pk=&pkt->cloud_pubk;

    mbedtls_pk_init( pk );




    if( ( ret = mbedtls_pk_parse_public_key( pk, buf, keylen )) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }


    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#if defined(MBEDTLS_ERROR_C)
    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
        mbedtls_strerror( ret, (char *) buf, sizeof( buf ) );
        mbedtls_printf( "  !  Last error was: %s\n", buf );
    }
#endif

    return( exit_code );
}



int cloud_rsa_priv_key_int(  enc_cloud_pk_t *pkt, unsigned char *pwd)
{
    int ret = 1;//, c;
    int exit_code = MBEDTLS_EXIT_FAILURE;
//    size_t i;//, olen = 0;


    const unsigned char *buf= cloud_priv_key_rsa_start;
    size_t buflen= (size_t)(cloud_priv_key_rsa_end-cloud_priv_key_rsa_start);

   // const char *pers = "mbedtls_pk_decrypt";
    mbedtls_pk_context *pk=&pkt->cloud_privk;
    mbedtls_pk_init( pk );




    mbedtls_printf( "\n  . Reading private key from buffer " );
    
    if( pwd == NULL )
        ret = mbedtls_pk_parse_key( pk, buf, buflen, NULL,(size_t) 0 );
    else
        ret = mbedtls_pk_parse_key( pk, buf, buflen,
                (const unsigned char *) pwd, (size_t)strlen((char*) pwd ) );


    if( ( ret) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }




    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    return( exit_code );
}

int cloud_rsa_decrypt(enc_cloud_pk_t *pkt,
        unsigned char *rsa_ciphertext,size_t cipher_len,
        unsigned char *rsa_decrypted , size_t *decrypt_len){

    int ret = 1;//, c;
    int exit_code = MBEDTLS_EXIT_FAILURE;

    mbedtls_pk_context *pk=&pkt->cloud_privk;
    mbedtls_entropy_context *entropy=&pkt->entropy;
    mbedtls_ctr_drbg_context *ctr_drbg=&pkt->ctr_drbg;

    const char *pers = "mbedtls_pk_decrypt";
    mbedtls_entropy_init( entropy );
    mbedtls_ctr_drbg_init( ctr_drbg );
    mbedtls_printf( "\n  . Seeding the random number generator..." );
    
    if( ( ret = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func,
                                       entropy, (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        -ret );
        goto exit;
    }

        /*
     * Decrypt the encrypted RSA data and print the result.
     */
    mbedtls_printf( "\n  . Decrypting the encrypted data" );
/*
( enc_cloud_pk_t *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
*/


    if( ( ret = mbedtls_pk_decrypt( pk, rsa_ciphertext, cipher_len, rsa_decrypted, decrypt_len, *decrypt_len,
                            mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n",
                        -ret );
        goto exit;
    }

    mbedtls_printf( "\n  . OK\n\n" );
  //  mbedtls_printf( "The decrypted result is: '%s'\n\n", rsa_decrypted );



exit:
    mbedtls_entropy_free( entropy );
    mbedtls_ctr_drbg_free( ctr_drbg );
    return( exit_code );


}

int cloud_rsa_encrypt(enc_cloud_pk_t *pkt,
        unsigned char *rsa_plaintext, size_t ilen,
        unsigned char *rsa_ciphertext, size_t *olen
        ){
    int ret = 1;//, c;
    size_t i;

    mbedtls_pk_context *pk=&pkt->cloud_privk;
    mbedtls_entropy_context *entropy=&pkt->entropy;
    mbedtls_ctr_drbg_context *ctr_drbg=&pkt->ctr_drbg;
    int exit_code = MBEDTLS_EXIT_FAILURE;

    const char *pers = "mbedtls_pk_encrypt";

    mbedtls_ctr_drbg_init( ctr_drbg );
    mbedtls_entropy_init( entropy );
    
    mbedtls_printf( "\n  . Seeding the random number generator..." );

    if( ( ret = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func,
                                       entropy, (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        -ret );
        goto exit;
    }

    /*
     * Calculate the RSA encryption of the hash.
     */
    mbedtls_printf( "\n  . Generating the encrypted value" );
    fflush( stdout );

    if( ( ret = mbedtls_pk_encrypt( pk, rsa_plaintext, ilen,
                            rsa_ciphertext, olen, *olen,
                            mbedtls_ctr_drbg_random, ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n",
                        -ret );
        goto exit;
    }


    // for( i = 0; i < *olen; i++ )
    // {
    //     mbedtls_printf( "%02X%s", rsa_ciphertext[i],
    //              ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
    // }


    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", "result-enc.txt" );
    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_entropy_free( entropy );
    mbedtls_ctr_drbg_free( ctr_drbg );

    return( exit_code );

}



