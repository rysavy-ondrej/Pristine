//
//  main.c
//  SecureChannel
//
//  Created by Ondrej Rysavy on 21/12/14.
//  Copyright (c) 2014 Brno University of Technology. All rights reserved.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/select.h>
#include "securechannel.h"
#include "udt.h"


#define MAXLINE 500
#define PROGRAM "SecureChannel "
#define PROGRAM_INFO "Secure Channel Demo, version 0.1 (Jan 08, 2015)\n\n"


typedef struct flow_info
{
    in_addr_t remote_address;
    in_port_t remote_port;
    in_port_t local_port;
} flow_info_t;

int flow_info_is_valid(flow_info_t *flow_info)
{
    return !(flow_info->remote_address == 0 || flow_info->remote_port == 0 || flow_info->local_port == 0);
}

#include <time.h>
void fprint_timestamp(FILE *f)
{
    time_t current_time;
    struct tm * time_info;
    char timeString[64];  // space for "HH:MM:SS\0"
    
    time(&current_time);
    time_info = localtime(&current_time);
    
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", time_info);
    fprintf(f,"%s \n", timeString);
}


int main(int argc, char **argv ) {
    
    char configFilename[FILENAME_MAX];
    strcpy(configFilename,"sechan.cfg");
    
    flow_info_t flow_info;
    flow_info.remote_address = htonl(0x7f000001);   // set to 127.0.0.1
    flow_info.remote_port = 0;
    flow_info.local_port = 0;
    

    char ch;
    while ((ch = getopt(argc,argv,"p:R:P:C:h")) != -1) {
        switch(ch) {
            case 'p':
                flow_info.local_port = htons(atol(optarg));
                break;
            case 'R':
                flow_info.remote_address = inet_addr(optarg);
                break;
            case 'P':
                flow_info.remote_port = htons(atol(optarg));
                break;
            case 'C':
                strcpy(configFilename, optarg);
                break;
            case 'h':
                fprintf(stdout, PROGRAM_INFO);
                fprintf(stdout, "usage: sechan -p port -P port [-R address] [-C config-file]\n\n");
                fprintf(stdout, "  p port        : local UDP socket binds to given `port'\n" );
                fprintf(stdout, "  P port        : UDP datagrams will be sent to the remote `port'\n" );
                fprintf(stdout, "  R address     : UDP datagrams will be sent to the remote host \n                  as specified by `address' (implicit value is 127.0.0.1)\n" );
                fprintf(stdout, "  C config-file : a name of configuration file, if not specified\n                  then default file name is `sechan.cfg' \n\n" );
                exit(EXIT_SUCCESS);
        }
    }
    fprintf(stderr, PROGRAM_INFO);
    
    // Complain if something is missing or wrong.
    if (!flow_info_is_valid(&flow_info)) {
        fprintf(stderr, "Missing required arguments! Type '%s -h' for help.\n", PROGRAM);
        exit(EXIT_FAILURE);
    }
    
    int error_code;
    SC_initialize();
    
    SC_PROFILE profile;
    memset(&profile, 0, sizeof(SC_PROFILE));

    if ((error_code = SC_PROFILE_load_and_validate(configFilename, &profile))!= S_OK)
    {
        switch(error_code)
        {
            case E_FILE_NOT_FOUND: fprintf(stderr, "Error while loading profile from file `%s'.\n", configFilename); break;
            case E_CANNOT_PARSE_PROFILE: fprintf(stderr,"Error while parsing profile file `%s'.Invalid or incomplete structure.\n", configFilename); break;
            case E_CANNOT_FIND_CIPHER: fprintf(stderr,"Invalid cipher algorithm  `%s'.\nValid algorithms are aes-128-ecb  aes-192-ecb  aes-256-ecb  bf-ecb  cast5-ecb  des-ecb  des3  desx  rc2-ecb  rc5-ecb  seed-ecb\n", EVP_CIPHER_name(profile.enc_cipher)); break;
            case E_CANNOT_FIND_MD: fprintf(stderr,"Invalid digest algorithm `%s'.\nValid algorithms are md2  md4  md5  mdc2  rmd160  sha sha1\n", EVP_MD_name(profile.mac_digest)); break;
        }
        exit(EXIT_FAILURE);
    }
    //fprintf(stderr, "sizeof(SC_SDU_SECURED)=%d, sizeof(SC_SDU_HEADER)=%d, sizeof(SC_SDU)=%d, sizeof(SC_SDU_PLAIN)=%d\n", sizeof(SC_SDU_SECURED),sizeof(SC_SDU_HEADER),sizeof(SC_SDU),sizeof(SC_SDU_PLAIN));
    fprintf(stderr, "-- SECURE CHANNEL INFO --------------------------------------------------\n");
    fprintf(stderr, "Active profile:\n");
    SC_PROFILE_print(stderr, &profile);
    
    SC_CTX sending_ctx;
    SC_CTX receiving_ctx;
   
    SC_CTX_create(&sending_ctx,&profile,0, &flow_info.local_port, &flow_info.remote_port, sizeof(in_port_t));
    SC_CTX_create(&receiving_ctx,&profile,0,&flow_info.remote_port, &flow_info.local_port, sizeof(in_port_t));
    fprintf(stderr, "-------------------------------------------------------------------------\n");
    fprintf(stderr, "Write context:\n");
    SC_CTX_print(stderr, &sending_ctx);
    fprintf(stderr, "-------------------------------------------------------------------------\n");
    fprintf(stderr, "Read context:\n");
    SC_CTX_print(stderr, &receiving_ctx);
    
    int udt = udt_init(flow_info.local_port);
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    
    char buffer[80];
    fprintf(stderr, "-------------------------------------------------------------------------\n");
    fprintf(stderr, "Data channel from localhost:%d to %s:%d.\n", ntohs(flow_info.local_port), inet_ntop(AF_INET, &flow_info.remote_address, buffer, 80), ntohs(flow_info.remote_port));
    fprintf(stderr, "=========================================================================\n");
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(udt, &readfds);
    FD_SET(STDIN_FILENO, &readfds);
    
    unsigned long sdu_counter = 0;
    
    char inputdata[MAXLINE];
    while (select(udt+1, &readfds, NULL, NULL, NULL)) {
        if (FD_ISSET(STDIN_FILENO, &readfds))
        {
            memset(inputdata, 0, MAXLINE);
            if (fgets((char*)inputdata, MAXLINE-1, stdin)!=NULL)
            {
                int block_size = EVP_CIPHER_CTX_block_size(sending_ctx.cipher_ctx);
                int data_length= strlen((char*)inputdata);
                
                fprintf(stderr,"\n");fprint_timestamp(stderr);
                fprintf(stderr, "New message (length=%d):\n",data_length);
                BIO_dump_fp(stderr, inputdata, data_length);
                
                SC_SDU *sdu = SC_SDU_allocate(SC_SDU_TYPE_SECURED, &sending_ctx, data_length);
                sdu->content.secured.sequence_number = sdu_counter;
                sdu->content.secured.context_index = 0;
            
                char counter_block [block_size];
                SC_compute_counter(counter_block, block_size, &sending_ctx, sdu);
                SC_encrypt(sending_ctx.cipher_ctx, (char *)sdu->content.secured.fragment, inputdata, data_length, counter_block);
                SC_SDU_compute_digest(&sending_ctx, sdu);
                
                fprintf(stderr,"SDU (total size=%d):\n", SC_SDU_total_length(sdu));
                SC_SDU_dump_fp(stdout, &sending_ctx, sdu);
                fprintf(stderr, "\n");
                
                if (!udt_send(udt, flow_info.remote_address, flow_info.remote_port, (char*)sdu, SC_SDU_total_length(sdu)))
                {
                    perror(PROGRAM);
                }
                sdu_counter++;
                SC_SDU_free(sdu);
            }
            if (feof(stdin)) break;
        }
        if (FD_ISSET(udt, &readfds)) {
            memset(inputdata, 0, MAXLINE);
            char message[MAXLINE];
            int recv_len = udt_recv(udt, inputdata, MAXLINE, NULL, NULL);
            if (recv_len > 0)
            {
                SC_SDU *sdu = (SC_SDU*)inputdata;
                fprintf(stderr,"\n");fprint_timestamp(stderr);
                fprintf(stderr,"Received SDU (total size=%d):\n",SC_SDU_total_length(sdu));
                SC_SDU_dump_fp(stderr, &sending_ctx, sdu);
            
                // verify MAC of the message...
                int sdu_correct = SC_SDU_verify_digest(&receiving_ctx, sdu);
                if (sdu_correct ==  TRUE)
                {
                    fprintf(stderr,"Integrity check: OK.\n");
                    
                    int message_length = SC_SDU_message_length(&receiving_ctx, sdu);
                    int block_size = EVP_CIPHER_CTX_block_size(receiving_ctx.cipher_ctx);
                    char counter_block [block_size];
                    SC_compute_counter(counter_block, block_size, &receiving_ctx, sdu);
                    SC_encrypt(receiving_ctx.cipher_ctx, message, (char *)sdu->content.secured.fragment, message_length, counter_block);
                    
                    fprintf(stderr, "Decoded message (length=%d):\n",message_length);
                    BIO_dump_fp(stderr, message, message_length);
                    fprintf(stderr, "\n");
                    
                    /* Add a NULL terminator. We are expecting printable text */
                    message[message_length] = '\0';
                    fputs((char*)message, stdout);
                    fflush(stdout);
                }
                else
                {
                    fprintf(stderr,"Integrity check: Failed.\nMessage dropped.\n");
                }
            }
        }
        FD_ZERO(&readfds);
        FD_SET(udt, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
    }
    
    SC_CTX_destroy(&sending_ctx);
    SC_CTX_destroy(&receiving_ctx);
        
    return EXIT_SUCCESS;
}