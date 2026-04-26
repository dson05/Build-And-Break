#include "atm.h"
#include "ports.h"
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* splits a command into whitespace-delimited arguments */
static int split(char *line, char **argv, int max_args) {

    int argc = 0;
    char *tok = strtok(line, " \t\r\n");

    while(tok != NULL && argc < max_args) {
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

/* checks an account name is alphabetic and in bounds */
static int valid_name(const char *name) {

    int len = 0;

    if(name == NULL || *name == '\0') {
        return 0;
    }

    while(*name != '\0') {
        if (!isalpha((unsigned char)*name)) {
            return 0;
        }
        if (++len > 250) {
            return 0;
        }

        name++;
    }

    return 1;
}

/* checks a pin is exactly four digits */
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

/* parses a nonnegative integer amount without overflowing */
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

/* sends a request to the bank and captures its reply */
static int bank_request(ATM *atm, char *request, char *response, size_t response_len) {

    ssize_t n;

    atm_send(atm, request, strlen(request));
    n = atm_recv(atm, response, response_len - 1);
    if(n < 0) {
        return 0;
    }

    response[n] = '\0';
    return 1;
}

ATM* atm_create() {

    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL) {
        perror("Could not allocate ATM");
        exit(1);
    }

    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    /* clear session state */
    atm->logged_in = 0;
    atm->current_user[0] = '\0';

    return atm;
}

void atm_free(ATM *atm) {
    if(atm != NULL) {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len) {
    return sendto(atm->sockfd, data, data_len, 0, (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len) {
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command) {

    char *argv[4];
    int argc = split(command, argv, 4);

    /* route user command */
    if(argc == 0) {
        printf("Invalid command\n");
    }
    else if(strcmp(argv[0], "begin-session") == 0) {

        /* start a session after card and pin checks */
        char request[300];
        char response[1000];
        char card_name[256];
        char card_pin[100];
        char entered_pin[100];
        FILE *card;

        if(atm->logged_in) {
            printf("A user is already logged in\n");
            return;
        }
        if(argc != 2 || !valid_name(argv[1])) {
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        sprintf(request, "exists %s", argv[1]);
        if(!bank_request(atm, request, response, sizeof(response)) ||
           strcmp(response, "OK") != 0) {

            printf("No such user\n");
            return;
        }

        sprintf(card_name, "%s.card", argv[1]);
        card = fopen(card_name, "r");
        if(card == NULL) {
            printf("Unable to access %s's card\n", argv[1]);
            return;
        }
        if(fgets(card_pin, sizeof(card_pin), card) == NULL) {
            card_pin[0] = '\0';
        }
        fclose(card);
        card_pin[strcspn(card_pin, "\r\n")] = '\0';

        printf("PIN? ");
        fflush(stdout);
        if(fgets(entered_pin, sizeof(entered_pin), stdin) == NULL) {
            printf("Not authorized\n");
            return;
        }
        entered_pin[strcspn(entered_pin, "\r\n")] = '\0';

        if(!valid_pin(entered_pin) || strcmp(entered_pin, card_pin) != 0) {
            printf("Not authorized\n");
            return;
        }

        sprintf(request, "auth %s %s", argv[1], entered_pin);
        if(!bank_request(atm, request, response, sizeof(response)) || strcmp(response, "OK") != 0) {

            printf("Not authorized\n");
            return;
        }

        atm->logged_in = 1;
        strcpy(atm->current_user, argv[1]);
        printf("Authorized\n");
    }
    else if(strcmp(argv[0], "withdraw") == 0) {

        /* ask bank to debit current user */
        char request[300];
        char response[1000];
        int amount;

        if(!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }
        if(argc != 2 || !parse_amount(argv[1], &amount)) {
            printf("Usage: withdraw <amt>\n");
            return;
        }

        sprintf(request, "withdraw %s %d", atm->current_user, amount);
        if(!bank_request(atm, request, response, sizeof(response)) || strcmp(response, "OK") != 0) {
            printf("Insufficient funds\n");
            return;
        }

        printf("$%d dispensed\n", amount);
    }
    else if(strcmp(argv[0], "balance") == 0) {

        /* request current balance */
        char request[300];
        char response[1000];

        if(!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }
        if(argc != 1) {

            printf("Usage: balance\n");
            return;
        }

        sprintf(request, "balance %s", atm->current_user);
        if(bank_request(atm, request, response, sizeof(response)) && strncmp(response, "BAL ", 4) == 0) {
            printf("$%s\n", response + 4);
        }
        else {

            printf("No user logged in\n");
        }
    }
    else if(strcmp(argv[0], "end-session") == 0) {

        /* clear current session */
        if(!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }
        if(argc != 1) {
            printf("Invalid command\n");
            return;
        }

        atm->logged_in = 0;
        atm->current_user[0] = '\0';
        printf("User logged out\n");
    }
    else {

        printf("Invalid command\n");
    }
}
