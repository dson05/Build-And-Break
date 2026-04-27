#ifndef __ATM_H__
#define __ATM_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "crypto.h"

typedef struct _ATM {
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in atm_addr;

    /* shared AES-256-GCM key loaded from the .atm init file */
    unsigned char key[KEY_SIZE];

    /* current session */
    int logged_in;
    char current_user[251];
} ATM;

ATM* atm_create();
int atm_load_key(ATM *atm, const char *path);
void atm_free(ATM *atm);
ssize_t atm_send(ATM *atm, char *data, size_t data_len);
ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len);
void atm_process_command(ATM *atm, char *command);

#endif
