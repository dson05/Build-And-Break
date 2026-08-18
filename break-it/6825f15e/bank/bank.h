/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * Commands from stdin be handled by bank_process_local_command.
 *
 * Remote commands from the ATM should be handled by
 * bank_process_remote_command.
 *
 * The Bank can read both .card files AND .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "security.h"

typedef struct bank_user
{
    char *name;
    char pin[5];
    int balance;
    unsigned char card_secret[CARD_SECRET_LEN];
    int session_active;
    unsigned char session_key[SESSION_KEY_LEN];
    unsigned int last_counter;
    struct bank_user *next;
} bank_user;

typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    // Protocol state
    bank_user *users;
    unsigned char master_key[MASTER_KEY_LEN];
} Bank;

Bank* bank_create(const char *init_path);
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);

#endif
