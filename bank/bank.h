#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "crypto.h"

#define BANK_MAX_USERS 1000
#define BANK_NONCE_BYTES 8
#define BANK_NONCE_RING 1024

/* one bank account */
typedef struct _User {
    char name[251];
    char pin[5];
    unsigned char card_secret[SECRET_SIZE];
    int balance;
} User;

typedef struct _Bank {
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    /* shared AES-256-GCM key loaded from the .bank init file */
    unsigned char key[KEY_SIZE];

    /* recently accepted request nonces; used to drop replays */
    unsigned char nonces[BANK_NONCE_RING][BANK_NONCE_BYTES];
    int nonce_used[BANK_NONCE_RING];
    int nonce_idx;

    /* in-memory accounts */
    User users[BANK_MAX_USERS];
    int num_users;
} Bank;

Bank* bank_create();
int bank_load_key(Bank *bank, const char *path);
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);

#endif
