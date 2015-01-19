/*
 ============================================================================
 Name        : rdpconnect.c
 Author      : Ondrej Rysavy
 Date        : Feb 26, 2009
 Copyright   : (c) Brno University of Technology
 Description : Simple UDT example.

 Allows to create an UDT end-point that communicates with the opposite side.
 Example:
 eva> ./udtdemo -p 15000 -P 15001
 eva> ./udtdemo -p 15001 -P 15000

 Written line on one side is send to the opposite one after ENTER is pressed
 and vice versa.
 ============================================================================
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "udt.h"

#define MAXLINE 500
#define PROGRAM "sechan"
#define PROGRAM_INFO "Secure Channel Demo, version 0.1 (Jan 08, 2015)\n\n"

in_addr_t remote_addr = htonl(0x7f000001);
in_port_t remote_port = 0;
in_port_t local_port = 0;


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * This function encrypts a plaintext using the given key and IV. It returns
 * length of encrypted message. "ciphertext" contains encrypted text.
 */
int crypto_aes_256_cbc_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

int crypto_aes_256_cbc_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int plaintext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
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
 */
int crypto_ctr_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *source, unsigned char *target, int length, unsigned char *counter)
{
    // only ECB mode is supported!
    if (EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_ECB_MODE)
        return -1;
    
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    unsigned char buffer[length+block_size];
    int offset = 0;
    // encrypt counter as many times as necessary
    for (int i = 0; i <= length / block_size; i++)
    {
        int encbytes = 0;
        EVP_EncryptUpdate(ctx, &buffer[offset], &encbytes, counter, block_size);
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

// Intialize stuff related to cryptolib.
void crypto_init()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void crypto_shutdown()
{
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    
}


/* Sending BIO pipeline */
BIO *bio_send_source;
BIO *bio_send_sink;
BIO *bio_header_writer;
BIO *bio_content_encryptor;
BIO *bio_integrity_maker;
/* Receiving BIO pipeline */


int main(int argc, char **argv ) {
    int counter = 0;
    char ch;
	char buf[80];
	unsigned char sendline[MAXLINE];
    unsigned char templine[MAXLINE];
	unsigned char recvline[MAXLINE];
    
    /* A 256 bit key */
    unsigned char *key = (unsigned char*) "01234567890123456789012345678901";
    
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    if(1 != EVP_EncryptInit_ex(ctx,  EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();
    
	int udt;

	while ((ch = getopt(argc,argv,"p:R:P:h")) != -1) {
		switch(ch) {
		case 'p':
				local_port = htons(atol(optarg));
			break;
		case 'R':
				 remote_addr = inet_addr(optarg);
			break;
		case 'P':
				remote_port = htons(atol(optarg));
			break;
		case 'h':
			fprintf(stdout, PROGRAM_INFO);
			fprintf(stdout, "usage: sechan -p port -P port [-R address]\n\n");
			fprintf(stdout, "  p port    : local UDP socket binds to `port'\n" );
			fprintf(stdout, "  P port    : UDP datagrams will be sent to the remote `port'\n" );
			fprintf(stdout, "  R address : UDP datagrams will be sent to the remote host \n              as specified by `address' (an implicit is 127.0.0.1)\n\n" );
			exit(EXIT_SUCCESS);
		}
	}
	fprintf(stderr, PROGRAM_INFO);
	// Complain if something is missing or wrong.
	if (remote_addr == 0 || remote_port == 0 || local_port == 0) {
		fprintf(stderr, "Missing required arguments! Type '%s -h' for help.\n", PROGRAM);
		exit(EXIT_FAILURE);
	}
    
    crypto_init();

    udt = udt_init(local_port);
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    
	fprintf(stderr, "Data channel from localhost:%d to %s:%d.\n", ntohs(local_port), inet_ntop(AF_INET, &remote_addr, buf, 80), ntohs(remote_port));
	fprintf(stderr, "Write data content, press ENTER to send the packet.\n");

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(udt, &readfds);
	FD_SET(STDIN_FILENO, &readfds);
	while (select(udt+1, &readfds, NULL, NULL, NULL)) {
        // SEND:
		if (FD_ISSET(STDIN_FILENO, &readfds) && fgets((char*)sendline, MAXLINE, stdin)>0) {

            memcpy(templine+12, &counter, 4);
            memcpy(templine+8,  &counter, 4);
            memcpy(templine+4,  &counter, 4);
            // least four bytes are used as 32-bit subcounter
            memset(templine, 0, 4);
            // encrypt it:
            int ciphertext_len = crypto_ctr_encrypt(ctx, sendline, templine+16, strlen((char*)sendline), templine);
            
			if (!udt_send(udt, remote_addr, remote_port, templine+12, ciphertext_len+4)) {
				perror("sechan: ");	// some error
			}
            counter++;
		}
        // RECV:
		if (FD_ISSET(udt, &readfds)) {
            memset(recvline, 0, MAXLINE);
			int recv_len = udt_recv(udt, recvline+12, MAXLINE, NULL, NULL);
            // reset subcounter
            memset(recvline, 0, 4);
            // expand counter value
            memcpy(recvline+4, recvline+12, 4);
            memcpy(recvline+8, recvline+12, 4);
            
            printf("Received message is:\n");
            BIO_dump_fp(stdout, (char*)recvline+12, recv_len);
            
            printf("Decrypted message is:\n");
            
            /* Decrypt the ciphertext */
            int decryptedtext_len = crypto_ctr_encrypt(ctx, recvline+16, templine, recv_len-4, recvline);
            
            /* Add a NULL terminator. We are expecting printable text */
            templine[decryptedtext_len] = '\0';

			fputs((char*)templine, stdout);
		}
		// and again!
		FD_ZERO(&readfds);
		FD_SET(udt, &readfds);
		FD_SET(STDIN_FILENO, &readfds);
	}
    
    crypto_shutdown();
    EVP_CIPHER_CTX_free(ctx);
    
	return EXIT_SUCCESS;
}
