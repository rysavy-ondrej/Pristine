//
//  securechannel.c
//  SecureChannel
//
//  Created by Ondrej Rysavy on 21/12/14.
//  Copyright (c) 2014 Brno University of Technology. All rights reserved.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <openssl/hmac.h>

#include "securechannel.h"

#define _MIN(x, y) (((x) < (y)) ? (x) : (y))


int SC_initialize()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    return S_OK;
}

int SC_finalize()
{
    EVP_cleanup();
    ERR_free_strings();
    return S_OK;
}

int SC_PROFILE_load_and_validate(char *fname, SC_PROFILE *profile)
{
    FILE *f;
    f = fopen (fname,"r");
    if (f == NULL) return E_FILE_NOT_FOUND;
    
    char cipher_name[32], digest_name[32];
    
    
    if (fscanf(f, "enc:%32s\nmac:%32s\nenckey:%32s\nseqkey:%32s\nmackey:%32s",
               cipher_name,digest_name,profile->enckey,profile->seqkey,profile->mackey)!= 5)
    {   // error in parsing file config file
        fclose(f);
        return E_CANNOT_PARSE_PROFILE;
    }

    fclose (f);
    profile->enc_cipher = EVP_get_cipherbyname(cipher_name);
    profile->mac_digest = EVP_get_digestbyname(digest_name);
    if (profile->enc_cipher == NULL) return E_CANNOT_FIND_CIPHER;
    if (profile->mac_digest == NULL) return E_CANNOT_FIND_MD;
    return S_OK;
}


void SC_PROFILE_print(FILE *f, SC_PROFILE *profile)
{
    fprintf(f, "enc:%s (keylen=%d, block size=%d)\n", EVP_CIPHER_name(profile->enc_cipher), EVP_CIPHER_key_length(profile->enc_cipher), EVP_CIPHER_block_size(profile->enc_cipher));
    fprintf(f, "mac:%s (len=%d)\n", EVP_MD_name(profile->mac_digest), EVP_MD_size(profile->mac_digest));
    fprintf(f, "enckey:%s\n", profile->enckey);
    fprintf(f, "seqkey:%s\n", profile->seqkey);
    fprintf(f, "mackey:%s\n", profile->mackey);
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * Length of key associated with the context depends on the key required by cipher algorithm.
 */
int SC_CTX_key_length(SC_CTX *ctx)
{
    return EVP_CIPHER_CTX_key_length(ctx->cipher_ctx);
}

int SC_CTX_create(SC_CTX *ctx, SC_PROFILE *profile)
{
    if(!(ctx->cipher_ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
        return E_FAIL;
    }
    if(!(ctx->digest_ctx = EVP_MD_CTX_create()))
    {
        handleErrors();
        return E_FAIL;
    }
    
    if(EVP_EncryptInit(ctx->cipher_ctx, profile->enc_cipher, (unsigned char*)profile->enckey, NULL) != 1)
    {
        handleErrors();
        return E_FAIL;
    }

    if(EVP_DigestInit(ctx->digest_ctx, profile->mac_digest) != 1)
    {
        handleErrors();
        return E_FAIL;
    }
    memcpy(&ctx->profile, profile, sizeof(SC_PROFILE));
    return S_OK;
}

void SC_CTX_destroy(SC_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx->cipher_ctx);
    EVP_MD_CTX_destroy(ctx->digest_ctx);
}

/*
 * Allocates SDU record according request type, current context and length of data.
 *
 * If secured reord is required then this function includes 
 * data length that needs to be accomodated and expected HMAC size to calculation of 
 * the total record size.
 *
 * Allocated record is zeroed.
 */
SC_SDU *SC_SDU_allocate(int sdu_type, SC_CTX *ctx, int message_length)
{
    SC_SDU *new_sdu = NULL;
    switch (sdu_type)
    {
        case SC_SDU_TYPE_PLAIN:
            new_sdu = (SC_SDU*)calloc(message_length+sizeof(SC_SDU_HEADER), sizeof(uint8_t));
            new_sdu->header.type = sdu_type;
            new_sdu->header.length = message_length;
        case SC_SDU_TYPE_SECURED:
        {
            int digest_size = EVP_MD_size(ctx->profile.mac_digest);
            int content_length = sizeof(SC_SDU_SECURED) + message_length + digest_size;
            new_sdu = (SC_SDU*)calloc(sizeof(SC_SDU_HEADER)+content_length, sizeof(uint8_t));
            new_sdu->header.type = sdu_type;
            new_sdu->header.length = content_length;
        }
    }
    return new_sdu;
}

int SC_SDU_total_length(SC_SDU *sdu)
{
    return sizeof(SC_SDU_HEADER) + sdu->header.length;
}

int SC_SDU_message_length(SC_CTX *ctx, SC_SDU *sdu)
{
    int digest_size = EVP_MD_size(ctx->profile.mac_digest);
    switch (sdu->header.type)
    {
        case SC_SDU_TYPE_PLAIN:   return sdu->header.length;
        case SC_SDU_TYPE_SECURED: return sdu->header.length - sizeof(SC_SDU_SECURED) - digest_size;
    }
    return 0;
}

void SC_SDU_dump_fp(FILE*f, SC_CTX *ctx, SC_SDU *sdu)
{
    fprintf(f, "Hdr=[type=%d, length=%d]\n",sdu->header.type,sdu->header.length);
    switch (sdu->header.type)
    {
        case SC_SDU_TYPE_PLAIN:
            BIO_dump_fp(f, (char*)sdu->content.plain.data, sdu->header.length);
            break;
            
        case SC_SDU_TYPE_SECURED:
        {
            int digest_size = EVP_MD_size(ctx->profile.mac_digest);
            int message_length = SC_SDU_message_length(ctx,sdu);
            fprintf(f, "Sec=[sequence=%llu, epoch=%d]\n",sdu->content.secured.sequence_number,sdu->content.secured.context_index);
            fprintf(f, "Data (length=%d):\n",message_length);
            BIO_dump_fp(f, (char*)sdu->content.secured.fragment, message_length);
            fprintf(f, "HMAC (length=%d):\n", digest_size);
            BIO_dump_fp(f, (char*)&sdu->content.secured.fragment[message_length], digest_size);
        }
    }
}


// Counter has always at least 128 bits. Its structure is following:
//           +-----------+-----------------+-----+----------+
// parts:    |   SUBCNT  |        SEQ#     | EPO | NONCE    >
//           +-----------+-----------------+-----+----------+
// len:       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
int SC_compute_counter(char *counter_block, int block_size, SC_CTX *ctx, SC_SDU *sdu)
{
    assert(block_size==8 || block_size==16);
    #define SUBCOUNTER_LENGTH 4
    switch(block_size)
    {
        case 8: // EPO and NONCE is not used for this length and SEQ is truncated to 32bits
        {
            fprintf(stderr, "block size=8\n");
            
            // four bytes are reserved for sub-counter
            memset(counter_block, 0, SUBCOUNTER_LENGTH);
            
            // next bytes are reserved for sequence numbers:
            memcpy(counter_block + SUBCOUNTER_LENGTH, &sdu->content.secured, 4);
            return 8;
        }
        case 16:
        {
            // four bytes are reserved for sub-counter
            memset(counter_block, 0, SUBCOUNTER_LENGTH);
            
            // next bytes are reserved for sequence numbers:
            memcpy(counter_block + SUBCOUNTER_LENGTH,
                   &sdu->content.secured,
                   sizeof(SC_SDU_SECURED));
            
            int nonce_offset = SUBCOUNTER_LENGTH + sizeof(SC_SDU_SECURED);
            int keylen = SC_CTX_key_length(ctx);
            int nonce_length = block_size - nonce_offset;
            
            memcpy(counter_block + nonce_offset, ctx->profile.seqkey, _MIN(keylen,nonce_length) );
            return nonce_offset + _MIN(keylen,nonce_length);
        }
        default: return E_INVALID_BLOCK_SIZE;
    }
}

/*
 * Compute digest of the record and store it at the end of record's fragment.
 * It assumes that record is intialized and valid.
 */
void SC_SDU_compute_digest(SC_CTX *ctx, SC_SDU *sdu)
{
    switch (sdu->header.type)
    {
        // This operation is valid only for secured records.
        case SC_SDU_TYPE_SECURED:
        {
            int keylen = SC_CTX_key_length(ctx);
            uint32_t digest_size = EVP_MD_size(ctx->profile.mac_digest);
            int sdu_length = SC_SDU_total_length(sdu);
            uint32_t md_length;
            int message_length = SC_SDU_message_length(ctx,sdu);
        
            HMAC(ctx->profile.mac_digest, ctx->profile.mackey, keylen, (uint8_t*)sdu,sdu_length-digest_size,&sdu->content.secured.fragment[message_length],&md_length);
            assert(digest_size == md_length);
        }
    }
}

int SC_SDU_verify_digest(SC_CTX *ctx, SC_SDU *sdu)
{
    switch (sdu->header.type)
    {
        // This operation is valid only for secured records.
        case SC_SDU_TYPE_SECURED:
        {
            uint8_t md_buffer[EVP_MAX_MD_SIZE];
            
            int keylen = SC_CTX_key_length(ctx);
            uint32_t digest_size = EVP_MD_size(ctx->profile.mac_digest);
            int sdu_length = SC_SDU_total_length(sdu);
            uint32_t md_length;
            int message_length = SC_SDU_message_length(ctx,sdu);
            
            HMAC(ctx->profile.mac_digest, ctx->profile.mackey, keylen, (uint8_t*)sdu,sdu_length-digest_size, md_buffer, &md_length);
            
            assert(digest_size == md_length);
            
            if(memcmp(&sdu->content.secured.fragment[message_length],md_buffer, _MIN(digest_size,EVP_MAX_MD_SIZE))==0)
                 return TRUE;
            else return FALSE;
        }
    }
    return TRUE;
}

/*
 * Function applies counter mode encryption using ECB mode cipher initialized in contex
 * to encrypt/decrypt source buffer to target buffer. Array counter represents an initial counter value.
 *
 * Note, that following should be satisfied:
 * - to work securely, counter value must never be used twice for encrypting different data.
 * - counter length must be equal to block size of the cipher used with the provided context.
 *
 * Parameters:
 * ctx - cipher context, it should be initialized with ECB mode cipher
 * source - a source buffer to encrypt
 * target - a target buffer for storing encrypted data
 * length - a length of data to be encrypted
 * counter - a block of data representing counter used in CTR mode
 *
 * RETURN VALUES:
 *  This function returns length of encrypted data on success. On fail it returns one of the following error:
 *  E_INVALID_CIPHER_CTX - provided ctx object does not represent initialized cipher algorithm in ECB mode.
 */
int SC_encrypt(EVP_CIPHER_CTX *ctx,  char *target,  char *source,  int length,  char *counter)
{
    // only ECB mode is supported!
    if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_ECB_MODE)
        return E_INVALID_CIPHER_CTX;
    
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    char buffer[length+block_size];
    int offset = 0;
    // encrypt counter as many times as necessary
    for (int i = 0; i <= length / block_size; i++)
    {
        int encbytes = 0;
        EVP_EncryptUpdate(ctx, (unsigned char*)(&buffer[offset]), &encbytes, (unsigned char*)counter, block_size);
        offset += encbytes;
        // increment counter:
        for (int j = 0; j < block_size / sizeof(unsigned char); j++)
            if (++counter[j]) break;
    }
    // in buffer, we have encrypted counter ->  xor it with input to produce encrypted data
    for(int i = 0; i <= length; i++)
    {
        target[i] = buffer[i] ^ source[i];
    }
    return length;
}

