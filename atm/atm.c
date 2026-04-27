#include "atm.h"
#include "ports.h"
#include "crypto.h"
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#define ATM_NONCE_BYTES 8
#define ATM_RECV_ATTEMPTS 6

/* splits a command into whitespace-delimited arguments */
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
    return max_args + 1;
}

/* checks an account name is alphabetic and in bounds */
static int valid_name(const char *name) {

    int len = 0;

    if (name == NULL || *name == '\0') {
        return 0;
    }

    while (*name != '\0') {
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

    if (pin == NULL) {
        return 0;
    }

    for (i = 0; i < 4; i++) {
        if (!isdigit((unsigned char)pin[i])) {
            return 0;
        }
    }

    return pin[4] == '\0';
}

/* parses a nonnegative integer amount without overflowing */
static int parse_amount(const char *text, int *amount) {

    long val = 0;

    if (text == NULL || *text == '\0') {
        return 0;
    }

    while (*text != '\0') {
        if (!isdigit((unsigned char)*text)) {
            return 0;
        }
        val = val * 10 + (*text - '0');
        if (val > INT_MAX) {
            return 0;
        }
        text++;
    }

    *amount = (int)val;
    return 1;
}

/* checks a hex string is exactly hex_len hex chars */
static int valid_hex(const char *s, size_t hex_len) {

    size_t i;

    if (s == NULL) {
        return 0;
    }
    for (i = 0; i < hex_len; i++) {
        if (!isxdigit((unsigned char)s[i])) {
            return 0;
        }
    }
    return s[hex_len] == '\0';
}

/* sends an encrypted request and returns the matching plaintext reply */
static int bank_request(ATM *atm, const char *plain_request, char *plain_response, size_t response_size) {

    unsigned char nonce[ATM_NONCE_BYTES];
    char nonce_hex[2 * ATM_NONCE_BYTES + 1];
    char wire_plain[1024];
    unsigned char wire[1024];
    unsigned char recv_buf[1024];
    unsigned char dec_buf[1024];
    int wlen;
    ssize_t n;
    int dlen;
    int attempts;
    int header_len = 2 + 2 * ATM_NONCE_BYTES + 1;
    int reply_len;

    if (!rand_bytes(nonce, ATM_NONCE_BYTES)) {
        return 0;
    }
    to_hex(nonce, ATM_NONCE_BYTES, nonce_hex);

    snprintf(wire_plain, sizeof(wire_plain), "R %s %s", nonce_hex, plain_request);
    wlen = aead_seal(atm->key, (unsigned char *)wire_plain, strlen(wire_plain), wire);
    if (wlen < 0) {
        return 0;
    }
    atm_send(atm, (char *)wire, wlen);

    /* loop in case attacker injected junk or replayed an older response */
    for (attempts = 0; attempts < ATM_RECV_ATTEMPTS; attempts++) {

        n = atm_recv(atm, (char *)recv_buf, sizeof(recv_buf));
        if (n < 0) {
            return 0;
        }
        dlen = aead_open(atm->key, recv_buf, n, dec_buf);
        if (dlen < header_len || dlen >= (int)sizeof(dec_buf)) {
            continue;
        }
        /* require server tag, the same nonce we just sent, and a separator */
        if (dec_buf[0] != 'A' || dec_buf[1] != ' ' || dec_buf[header_len - 1] != ' ') {
            continue;
        }
        if (memcmp(dec_buf + 2, nonce_hex, 2 * ATM_NONCE_BYTES) != 0) {
            continue;
        }

        reply_len = dlen - header_len;
        if ((size_t)reply_len >= response_size) {
            return 0;
        }
        memcpy(plain_response, dec_buf + header_len, reply_len);
        plain_response[reply_len] = '\0';
        return 1;
    }

    return 0;
}

ATM* atm_create() {

    struct timeval tv;
    ATM *atm = (ATM*) malloc(sizeof(ATM));

    if (atm == NULL) {
        perror("Could not allocate ATM");
        exit(1);
    }

    atm->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&atm->rtr_addr, sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd, (struct sockaddr *)&atm->atm_addr, sizeof(atm->atm_addr));

    /* bound recv timeout so a silent or hostile network does not hang the ATM */
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(atm->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* clear session state */
    atm->logged_in = 0;
    atm->current_user[0] = '\0';

    return atm;
}

/* reads a hex-encoded shared key from the .atm init file */
int atm_load_key(ATM *atm, const char *path) {

    FILE *f;
    char hex[2 * KEY_SIZE + 1];
    size_t got;

    f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }
    got = fread(hex, 1, 2 * KEY_SIZE, f);
    fclose(f);
    if (got != 2 * KEY_SIZE) {
        return 0;
    }
    return from_hex(hex, atm->key, KEY_SIZE);
}

void atm_free(ATM *atm) {
    if (atm != NULL) {
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

    if (argc == 0) {
        printf("Invalid command\n");
        return;
    }

    if (strcmp(argv[0], "begin-session") == 0) {

        /* start a session after card and pin checks */
        char request[512];
        char response[256];
        char card_name[256];
        char card_secret_hex[SECRET_HEX_SIZE];
        char entered_pin[100];
        FILE *card;

        if (atm->logged_in) {
            printf("A user is already logged in\n");
            return;
        }
        if (argc != 2 || !valid_name(argv[1])) {
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        snprintf(request, sizeof(request), "exists %s", argv[1]);
        if (!bank_request(atm, request, response, sizeof(response)) || strcmp(response, "OK") != 0) {

            printf("No such user\n");
            return;
        }

        snprintf(card_name, sizeof(card_name), "%s.card", argv[1]);
        card = fopen(card_name, "r");
        if (card == NULL) {
            printf("Unable to access %s's card\n", argv[1]);
            return;
        }
        if (fgets(card_secret_hex, sizeof(card_secret_hex), card) == NULL) {
            card_secret_hex[0] = '\0';
        }
        fclose(card);
        card_secret_hex[strcspn(card_secret_hex, "\r\n")] = '\0';

        printf("PIN? ");
        fflush(stdout);
        if (fgets(entered_pin, sizeof(entered_pin), stdin) == NULL) {
            printf("Not authorized\n");
            return;
        }
        entered_pin[strcspn(entered_pin, "\r\n")] = '\0';

        /* sanity-check pin and card formats locally before contacting bank */
        if (!valid_pin(entered_pin) || !valid_hex(card_secret_hex, 2 * SECRET_SIZE)) {
            printf("Not authorized\n");
            return;
        }

        snprintf(request, sizeof(request), "auth %s %s %s", argv[1], entered_pin, card_secret_hex);
        if (!bank_request(atm, request, response, sizeof(response)) || strcmp(response, "OK") != 0) {

            printf("Not authorized\n");
            return;
        }

        atm->logged_in = 1;
        strcpy(atm->current_user, argv[1]);
        printf("Authorized\n");
        return;
    }

    if (strcmp(argv[0], "withdraw") == 0) {

        /* ask bank to debit current user */
        char request[300];
        char response[256];
        int amount;

        if (!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }
        if (argc != 2 || !parse_amount(argv[1], &amount)) {
            printf("Usage: withdraw <amt>\n");
            return;
        }

        snprintf(request, sizeof(request), "withdraw %s %d", atm->current_user, amount);
        if (!bank_request(atm, request, response, sizeof(response)) || strcmp(response, "OK") != 0) {
            printf("Insufficient funds\n");
            return;
        }

        printf("$%d dispensed\n", amount);
        return;
    }

    if (strcmp(argv[0], "balance") == 0) {

        /* request current balance */
        char request[300];
        char response[256];

        if (!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }
        if (argc != 1) {
            printf("Usage: balance\n");
            return;
        }

        snprintf(request, sizeof(request), "balance %s", atm->current_user);
        if (bank_request(atm, request, response, sizeof(response)) && strncmp(response, "BAL ", 4) == 0) {
            printf("$%s\n", response + 4);
            return;
        }

        printf("No user logged in\n");
        return;
    }

    if (strcmp(argv[0], "end-session") == 0) {

        /* clear current session */
        if (!atm->logged_in) {
            printf("No user logged in\n");
            return;
        }
        if (argc != 1) {
            printf("Invalid command\n");
            return;
        }

        atm->logged_in = 0;
        atm->current_user[0] = '\0';
        printf("User logged out\n");
        return;
    }

    printf("Invalid command\n");
}
