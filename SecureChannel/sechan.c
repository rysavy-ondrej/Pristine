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

int crypto_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
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

int crypto_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
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

// Intialize stuff related to cryptolib.
int crypto_init()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

int crypto_shutdown()
{
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
}

int main(int argc, char **argv ) {
	char ch;
	char buf[80];
	char sendline[MAXLINE];
    char templine[MAXLINE];
	char recvline[MAXLINE];
    
    /* A 256 bit key */
    unsigned char *key = "01234567890123456789012345678901";
    
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
		if (FD_ISSET(STDIN_FILENO, &readfds) && fgets(sendline, MAXLINE, stdin)>0) { // we have read a new line to send
            // generate new IV:
            RAND_bytes(templine, 16);
            // or, which may be faster (?)
            // RAND_pseudo_bytes(templine,16);
            
            // encrypt it:
            int ciphertext_len = crypto_encrypt(sendline, strlen(sendline), key, templine, templine+16);
			if (!udt_send(udt, remote_addr, remote_port, templine, ciphertext_len+16)) {
				perror("sechan: ");	// some error
			}
		}
		if (FD_ISSET(udt, &readfds)) {	// We have a new message to print
			int recv_len = udt_recv(udt, recvline, MAXLINE, NULL, NULL);
            
            printf("Encrypted message is:\n");
            BIO_dump_fp(stdout, recvline, recv_len);
            
            printf("Decrypted message is:\n");
            
            /* Decrypt the ciphertext */
            int decryptedtext_len = crypto_decrypt(recvline+16, recv_len-16, key, recvline,templine);
            
            /* Add a NULL terminator. We are expecting printable text */
            templine[decryptedtext_len] = '\0';

			fputs(templine, stdout);
		}
		// and again!
		FD_ZERO(&readfds);
		FD_SET(udt, &readfds);
		FD_SET(STDIN_FILENO, &readfds);
	}
    
    crypto_shutdown();
    
	return EXIT_SUCCESS;
}
