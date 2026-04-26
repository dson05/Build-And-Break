#include "bank.h"
#include "ports.h"
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* splits command into whitespace delimited arguments */
static int split(char *line, char **argv, int max_args) {

    int argc = 0;
    char *tok = strtok(line, " \t\r\n");

    while (tok != NULL && argc < max_args) {
        argv[argc++] = tok;
        tok = strtok(NULL, " \t\r\n");
    }

    if (tok == NULL) {
        return argc;
    }
    else {
        return max_args + 1;
    }
}

/* checks that account name is alphabetic and in range */
static int valid_name(const char *name) {

    int len = 0;

    if(name == NULL || *name == '\0') {
        return 0;
    }

    while(*name != '\0') {
        if(!isalpha((unsigned char)*name)) {
            return 0;
        }
        if(++len > 250) {
            return 0;
        }
        name++;
    }

    return 1;
}

/* checks pin is exactly 4 decimal digits */
static int valid_pin(const char *pin) {

    int i;

    if(pin == NULL) {
        return 0;
    }

    for(i = 0; i < 4; i++) {
        if(!isdigit((unsigned char)pin[i])) {
            return 0;
        }
    }

    return pin[4] == '\0';
}

/* parses nonnegative integer amount */
static int parse_amount(const char *text, int *amount) {

    long val = 0;

    if(text == NULL || *text == '\0') {
        return 0;
    }

    while(*text != '\0') {
        if(!isdigit((unsigned char)*text)) {
            return 0;
        }
        val = val * 10 + (*text - '0');
        if(val > INT_MAX) {
            return 0;
        }
        text++;
    }

    *amount = (int)val;
    return 1;
}

/* finds a bank user record via account name */
static User *find_user(Bank *bank, const char *name) {

    int i;

    for(i = 0; i < bank->num_users; i++) {
        if(strcmp(bank->users[i].name, name) == 0) {
            return &bank->users[i];
        }
    }

    return NULL;
}

Bank* bank_create() {

    Bank *bank = (Bank*) malloc(sizeof(Bank));

    if(bank == NULL) {
        perror("Could not allocate Bank");
        exit(1);
    }

    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    bank->num_users = 0;

    return bank;
}

void bank_free(Bank *bank) {

    if(bank != NULL) {

        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len) {
    return sendto(bank->sockfd, data, data_len, 0, (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len) {
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, char *command, size_t len) {

    char *argv[5];
    int argc;

    (void)len;
    argc = split(command, argv, 5);
    if(argc == 0) {
        printf("Invalid command\n");
    }
    else if(strcmp(argv[0], "create-user") == 0) {

        /* create user and card file */
        int balance;
        char card_name[256];
        FILE *card;

        if(argc != 4 || !valid_name(argv[1]) || !valid_pin(argv[2]) || !parse_amount(argv[3], &balance)) {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }

        if(find_user(bank, argv[1]) != NULL) {
            printf("Error:  user %s already exists\n", argv[1]);
            return;
        }
        if(bank->num_users >= 1000) {
            printf("Error creating card file for user %s\n", argv[1]);
            return;
        }

        sprintf(card_name, "%s.card", argv[1]);
        card = fopen(card_name, "r");
        if(card != NULL) {
            fclose(card);
            printf("Error creating card file for user %s\n", argv[1]);
            return;
        }

        card = fopen(card_name, "w");
        if(card == NULL) {
            printf("Error creating card file for user %s\n", argv[1]);
            return;
        }
        fprintf(card, "%s\n", argv[2]);
        fclose(card);

        strcpy(bank->users[bank->num_users].name, argv[1]);
        strcpy(bank->users[bank->num_users].pin, argv[2]);
        bank->users[bank->num_users].balance = balance;
        bank->num_users++;

        printf("Created user %s\n", argv[1]);
    }
    else if(strcmp(argv[0], "deposit") == 0) {

        /* add money to account */
        int amount;
        User *user;

        if(argc != 3 || !valid_name(argv[1]) || !parse_amount(argv[2], &amount)) {
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }

        user = find_user(bank, argv[1]);
        if(user == NULL) {
            printf("No such user\n");
            return;
        }

        if(amount > INT_MAX - user->balance) {
            printf("Too rich for this program\n");
            return;
        }

        user->balance += amount;
        printf("$%d added to %s's account\n", amount, argv[1]);
    }
    else if(strcmp(argv[0], "balance") == 0) {

        /* print account balance */
        User *user;

        if(argc != 2 || !valid_name(argv[1])) {
            printf("Usage:  balance <user-name>\n");
            return;
        }

        user = find_user(bank, argv[1]);

        if(user == NULL) {
            printf("No such user\n");
        }
        else {
            printf("$%d\n", user->balance);
        }
    }
    else {
        printf("Invalid command\n");
    }
}

void bank_process_remote_command(Bank *bank, char *command, size_t len) {

    char *argv[4];
    int argc;
    User *user;

    if(len >= 1000) {

        len = 999;
    }
    command[len] = '\0';
    argc = split(command, argv, 4);

    /* route atm request */
    if(argc == 2 && strcmp(argv[0], "exists") == 0) {

        /* confirm account exists */
        bank_send(bank, find_user(bank, argv[1]) == NULL ? "NO" : "OK", 2);
    }
    else if(argc == 3 && strcmp(argv[0], "auth") == 0) {

        /* verify login pin */
        user = find_user(bank, argv[1]);
        bank_send(bank, user != NULL && strcmp(user->pin, argv[2]) == 0 ? "OK" : "NO", 2);
    }
    else if(argc == 2 && strcmp(argv[0], "balance") == 0) {

        /* return account balance */
        char response[64];

        user = find_user(bank, argv[1]);
        if(user == NULL) {
            bank_send(bank, "NO", 2);
        }
        else {
            sprintf(response, "BAL %d", user->balance);
            bank_send(bank, response, strlen(response));
        }
    }
    else if(argc == 3 && strcmp(argv[0], "withdraw") == 0) {

        /* debit account if funds are available */
        int amount;

        user = find_user(bank, argv[1]);
        if(user == NULL || !parse_amount(argv[2], &amount)) {
            bank_send(bank, "NO", 2);
        }
        else if(amount > user->balance) {
            bank_send(bank, "NSF", 3);
        }
        else {
            user->balance -= amount;
            bank_send(bank, "OK", 2);
        }
    }
}
