/*
 *  AES-256 file encryption program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/* Enable definition of fileno() even when compiling with -std=c99. Must be
 * set before config.h, which pulls in glibc's features.h indirectly.
 * Harmless on other platforms. */
#include "aes_enc_dec.h"

#if 0
int aes_enc_dec(aes_t *aes_encdec_ctx )
{
    int ret = 0;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned int i, n;
    int mode, lastn;
    mbedtls_aes_context *aes_ctx= &aes_encdec_ctx->aes_ctx;    
    mbedtls_md_context_t *sha_ctx= &aes_encdec_ctx->sha_ctx;
    unsigned char *key=NULL;
    size_t keylen;
    char *p;
    unsigned char tmp[16];

    unsigned char diff;

    off_t offset;

    mbedtls_aes_init( aes_ctx );
    mbedtls_md_init( sha_ctx );

    ret = mbedtls_md_setup( sha_ctx, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 1 );
    if( ret != 0 )
    {
        mbedtls_printf( "  ! mbedtls_md_setup() returned -0x%04x\n", -ret );
        goto exit;
    }

    mode = aes_encdec_ctx->mode;

    //memset( buffer, 0, sizeof( buffer ) );

    if( mode != MODE_ENCRYPT && mode != MODE_DECRYPT )
    {
        mbedtls_fprintf( stderr, "invalide operation mode\n" );
        goto exit;
    }

   

    /*
     * Read the secret key from file or command line
     */
    key= aes_encdec_ctx->key;
    keylen= aes_encdec_ctx->keylen;

    if( mode == MODE_ENCRYPT )
    {
        unsigned char IVT[16],digestT[32];
        unsigned char *IV=IVT;//aes_encdec_ctx->IV;
        unsigned char *digest=digestT; //aes_encdec_ctx->digest;
        unsigned char *buffer=aes_encdec_ctx->enc_buffer;
        unsigned char *plain_buffer=aes_encdec_ctx->plain_buffer;
        off_t filesize=aes_encdec_ctx->plain_len;

        memset( IV,     0, 16 );
        memset( digest, 0, 32 );
        /*
         * Generate the initialization vector as:
         * IV = SHA-256( filesize || filename )[0..15]
         */
        for( i = 0; i < 8; i++ )
            buffer[i] = (unsigned char)( filesize >> ( i << 3 ) );

        p = "shiva_encryption";

        mbedtls_md_starts( sha_ctx );
        mbedtls_md_update( sha_ctx, buffer, 8 );
        mbedtls_md_update( sha_ctx, (unsigned char *) p, strlen( p ) );
        mbedtls_md_finish( sha_ctx, digest );

        memcpy( IV, digest, 16 );

        /*
         * The last four bits in the IV are actually used
         * to store the file size modulo the AES block size.
         */
        lastn = (int)( filesize & 0x0F );

        IV[15] = (unsigned char)
            ( ( IV[15] & 0xF0 ) | lastn );

 /*
        //  * Append the IV at the beginning of the output.
        //  */
        // if( fwrite( IV, 1, 16, fout ) != 16 )
        // {
        //     mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
        //     goto exit;
        // }
        memcpy(aes_encdec_ctx->IV,IV,16);


        /*
         * Hash the IV and the secret key together 8192 times
         * using the result to setup the AES context and HMAC.
         */
        memset( digest, 0,  32 );
        memcpy( digest, IV, 16 );

        for( i = 0; i < 8192; i++ )
        {
            mbedtls_md_starts( sha_ctx );
            mbedtls_md_update( sha_ctx, digest, 32 );
            mbedtls_md_update( sha_ctx, key, keylen );
            mbedtls_md_finish( sha_ctx, digest );
        }

        mbedtls_aes_setkey_enc( aes_ctx, digest, 256 );
        mbedtls_md_hmac_starts( sha_ctx, digest, 32 );

        /*
         * Encrypt and write the ciphertext.
         */
        aes_encdec_ctx->enc_len=0;
        for( offset = 0; offset < filesize; offset += 16 )
        {
            char tmpbuff[16];
            
            buffer=&aes_encdec_ctx->enc_buffer[offset];
            plain_buffer+=16;

            n = ( filesize - offset > 16 ) ? 16 : (int)
                ( filesize - offset );

            // if( fread( buffer, 1, n, fin ) != (size_t) n )
            // {
            //     mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", n );
            //     goto exit;
            // }
            
            memcpy(tmpbuff,plain_buffer,n);
            //mbedtls_printf("%x ",(unsigned int)plain_buffer);
            for( i = 0; i < 16; i++ ){
                //mbedtls_printf("%d ",(int)tmpbuff[i]*0xff);
                buffer[i] = (unsigned char)( tmpbuff[i] ^ IV[i] );
            }
            mbedtls_aes_crypt_ecb( aes_ctx, MBEDTLS_AES_ENCRYPT, buffer, buffer );
            mbedtls_md_hmac_update( sha_ctx, buffer, 16 );

            // if( fwrite( buffer, 1, 16, fout ) != 16 )
            // {
            //     mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
            //     goto exit;
            // }
            aes_encdec_ctx->enc_len +=16;
            memcpy( IV, buffer, 16 );
        }

        /*
         * Finally write the HMAC.
         */
        mbedtls_md_hmac_finish( sha_ctx, digest );
        memcpy(aes_encdec_ctx->digest,digest,32);

        // if( fwrite( digest, 1, 32, fout ) != 32 )
        // {
        //     mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
        //     goto exit;
        // }
    }

    if( mode == MODE_DECRYPT )
    {
        unsigned char IV[16];//=aes_encdec_ctx->IV;
        unsigned char digest[32];//=aes_encdec_ctx->digest;
        off_t filesize=aes_encdec_ctx->enc_len;
        unsigned char *buffer=aes_encdec_ctx->enc_buffer;
        unsigned char *plain_buffer=&aes_encdec_ctx->plain_buffer[0];
       // mbedtls_printf("Here1 enc_len=%ld dec_len=%u\n",filesize,aes_encdec_ctx->plain_len);
        /*
         *  The encrypted file must be structured as follows:
         *
         *        00 .. 15              Initialization Vector
         *        16 .. 31              AES Encrypted Block #1
         *           ..
         *      N*16 .. (N+1)*16 - 1    AES Encrypted Block #N
         *  (N+1)*16 .. (N+1)*16 + 32   HMAC-SHA-256(ciphertext)
         */
        // if( filesize < 48 )
        // {
        //     mbedtls_fprintf( stderr, "File too short to be encrypted.\n" );
        //     goto exit;
        // }

        // if( ( filesize & 0x0F ) != 0 )
        // {
        //     mbedtls_fprintf( stderr, "File size not a multiple of 16.\n" );
        //     goto exit;
        // }

        /*
         * Subtract the IV + HMAC length.
         */
        // filesize -= ( 16 + 32 );

        /*
         * Read the IV and original filesize modulo 16.
         */
        // if( fread( buffer, 1, 16, fin ) != 16 )
        // {
        //     mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 16 );
        //     goto exit;
        // }

        memcpy( IV, aes_encdec_ctx->IV, 16 );
        lastn = IV[15] & 0x0F;

        /*
         * Hash the IV and the secret key together 8192 times
         * using the result to setup the AES context and HMAC.
         */
        memset( digest, 0,  32 );
        memcpy( digest, IV, 16 );

        for( i = 0; i < 8192; i++ )
        {
            mbedtls_md_starts( sha_ctx );
            mbedtls_md_update( sha_ctx, digest, 32 );
            mbedtls_md_update( sha_ctx, key, keylen );
            mbedtls_md_finish( sha_ctx, digest );
        }

        mbedtls_aes_setkey_dec( aes_ctx, digest, 256 );
        mbedtls_md_hmac_starts( sha_ctx, digest, 32 );

        /*
         * Decrypt and write the plaintext.
         */
        aes_encdec_ctx->plain_len = 0;
        for( offset = 0; offset < filesize; offset += 16 )
        {
            // if( fread( buffer, 1, 16, fin ) != 16 )
            // {
            //     mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 16 );
            //     goto exit;
            // }
            unsigned char tmpbuff[16];

            buffer=&aes_encdec_ctx->enc_buffer[offset];
            plain_buffer+=16;

            memcpy( tmp, buffer, 16 );
            memcpy( tmpbuff, buffer, 16 );


            mbedtls_md_hmac_update( sha_ctx, tmpbuff, 16 );
            mbedtls_aes_crypt_ecb( aes_ctx, MBEDTLS_AES_DECRYPT, tmpbuff, tmpbuff );


            for( i = 0; i < 16; i++ ){
                buffer[i] = (unsigned char)( tmpbuff[i] ^ IV[i] );
            }


            memcpy( IV, tmp, 16 );

            n = ( lastn > 0 && offset == filesize - 16 )
                ? lastn : 16;

            
            memcpy(plain_buffer,buffer,n);
            aes_encdec_ctx->plain_len+=n;
            // if( fwrite( buffer, 1, n, fout ) != (size_t) n )
            // {
            //     mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", n );
            //     goto exit;
            // }
        }

        /*
         * Verify the message authentication code.
         */
        mbedtls_md_hmac_finish( sha_ctx, digest );

        // if( fread( buffer, 1, 32, fin ) != 32 )
        // {
        //     mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 32 );
        //     goto exit;
        // }

        /* Use constant-time buffer comparison */
        diff = 0;
        for( i = 0; i < 32; i++ )
            diff |= digest[i] ^ aes_encdec_ctx->digest[i];

        if( diff != 0 )
        {
            mbedtls_fprintf( stderr, "HMAC check failed: wrong key, "
                             "or file corrupted.\n" );
            goto exit;
        }
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    // if( fin )
    //     fclose( fin );
    // if( fout )
    //     fclose( fout );

     /* Zeroize all command line arguments to also cover
       the case when the user has missed or reordered some,
       in which case the key might not be in argv[4]. */
    // for( i = 0; i < (unsigned int) argc; i++ )
    //     mbedtls_platform_zeroize( argv[i], strlen( argv[i] ) );

    // mbedtls_platform_zeroize( IV,     sizeof( IV ) );
    // mbedtls_platform_zeroize( key,    sizeof( key ) );
    // mbedtls_platform_zeroize( tmp,    sizeof( tmp ) );
    // mbedtls_platform_zeroize( buffer, sizeof( buffer ) );
    // mbedtls_platform_zeroize( digest, sizeof( digest ) );

    //mbedtls_aes_free( aes_ctx );
    //mbedtls_md_free( sha_ctx );

    return( exit_code );
}
#else

int aes_enc_dec(aes_t *aes_encdec_ctx )
{
    int ret = 0;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned int i, n;
    int mode, lastn;
    mbedtls_aes_context *aes_ctx= &aes_encdec_ctx->aes_ctx;    
    mbedtls_md_context_t *sha_ctx= &aes_encdec_ctx->sha_ctx;
    unsigned char *key=NULL;
    size_t keylen;
    char *p;
    unsigned char tmp[16];

    unsigned char diff;

    off_t offset;

    mbedtls_aes_init( aes_ctx );
    mbedtls_md_init( sha_ctx );

    ret = mbedtls_md_setup( sha_ctx, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 1 );
    if( ret != 0 )
    {
        mbedtls_printf( "  ! mbedtls_md_setup() returned -0x%04x\n", -ret );
        goto exit;
    }

    mode = aes_encdec_ctx->mode;

    //memset( buffer, 0, sizeof( buffer ) );

    if( mode != MODE_ENCRYPT && mode != MODE_DECRYPT )
    {
        mbedtls_fprintf( stderr, "invalide operation mode\n" );
        goto exit;
    }

   

    /*
     * Read the secret key from file or command line
     */
    key= aes_encdec_ctx->key;
    keylen= aes_encdec_ctx->keylen;

    if( mode == MODE_ENCRYPT )
    {
        unsigned char IVT[16],digestT[32];
        unsigned char *IV=IVT;//aes_encdec_ctx->IV;
        unsigned char *digest=digestT; //aes_encdec_ctx->digest;
        unsigned char *buffer=aes_encdec_ctx->enc_buffer;
        unsigned char *plain_buffer=aes_encdec_ctx->plain_buffer;
        off_t filesize=aes_encdec_ctx->plain_len;

 
        memcpy( IV, aes_encdec_ctx->IV, 16 );

        mbedtls_aes_setkey_enc( aes_ctx, key, keylen*8 );

        aes_encdec_ctx->enc_len=filesize;

        mbedtls_aes_crypt_cbc( aes_ctx, MBEDTLS_AES_ENCRYPT,filesize,IV, plain_buffer, buffer );

    }

    if( mode == MODE_DECRYPT )
    {
        unsigned char IV[16];//=aes_encdec_ctx->IV;
        unsigned char digest[32];//=aes_encdec_ctx->digest;
        off_t filesize=aes_encdec_ctx->enc_len;
        unsigned char *buffer=aes_encdec_ctx->enc_buffer;
        unsigned char *plain_buffer=&aes_encdec_ctx->plain_buffer[0];


        memcpy( IV, aes_encdec_ctx->IV, 16 );

        memset( digest, 0,  32 );


        mbedtls_aes_setkey_dec( aes_ctx, key, keylen*8);
       // mbedtls_md_hmac_starts( sha_ctx, digest, 32 );

        /*
         * Decrypt and write the plaintext.
         */
        aes_encdec_ctx->plain_len = 0;

        mbedtls_aes_crypt_cbc( aes_ctx, MBEDTLS_AES_DECRYPT,filesize, IV, buffer, plain_buffer );


        
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    // if( fin )
    //     fclose( fin );
    // if( fout )
    //     fclose( fout );

     /* Zeroize all command line arguments to also cover
       the case when the user has missed or reordered some,
       in which case the key might not be in argv[4]. */
    // for( i = 0; i < (unsigned int) argc; i++ )
    //     mbedtls_platform_zeroize( argv[i], strlen( argv[i] ) );

    // mbedtls_platform_zeroize( IV,     sizeof( IV ) );
    // mbedtls_platform_zeroize( key,    sizeof( key ) );
    // mbedtls_platform_zeroize( tmp,    sizeof( tmp ) );
    // mbedtls_platform_zeroize( buffer, sizeof( buffer ) );
    // mbedtls_platform_zeroize( digest, sizeof( digest ) );

    //mbedtls_aes_free( aes_ctx );
    //mbedtls_md_free( sha_ctx );

    return( exit_code );
}

#endif
