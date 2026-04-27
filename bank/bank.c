#include "bank.h"
#include "ports.h"
#include "crypto.h"
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
    return max_args + 1;
}

/* checks that account name is alphabetic and in range */
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

/* checks pin is exactly 4 decimal digits */
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

/* parses nonnegative integer amount */
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

/* finds a bank user record via account name */
static User *find_user(Bank *bank, const char *name) {

    int i;

    for (i = 0; i < bank->num_users; i++) {
        if (strcmp(bank->users[i].name, name) == 0) {
            return &bank->users[i];
        }
    }

    return NULL;
}

/* returns 1 if this nonce was already accepted recently */
static int nonce_seen(Bank *bank, const unsigned char *nonce) {

    int i;

    for (i = 0; i < BANK_NONCE_RING; i++) {
        if (bank->nonce_used[i] && memcmp(bank->nonces[i], nonce, BANK_NONCE_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

static void nonce_remember(Bank *bank, const unsigned char *nonce) {

    memcpy(bank->nonces[bank->nonce_idx], nonce, BANK_NONCE_BYTES);
    bank->nonce_used[bank->nonce_idx] = 1;
    bank->nonce_idx = (bank->nonce_idx + 1) % BANK_NONCE_RING;
}

Bank* bank_create() {

    Bank *bank = (Bank*) malloc(sizeof(Bank));

    if (bank == NULL) {
        perror("Could not allocate Bank");
        exit(1);
    }

    bank->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&bank->rtr_addr, sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd, (struct sockaddr *)&bank->bank_addr, sizeof(bank->bank_addr));

    bank->num_users = 0;
    bank->nonce_idx = 0;
    memset(bank->nonce_used, 0, sizeof(bank->nonce_used));

    return bank;
}

/* reads a hex-encoded shared key from the .bank init file */
int bank_load_key(Bank *bank, const char *path) {

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
    return from_hex(hex, bank->key, KEY_SIZE);
}

void bank_free(Bank *bank) {

    if (bank != NULL) {

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
    if (argc == 0) {
        printf("Invalid command\n");
        return;
    }

    if (strcmp(argv[0], "create-user") == 0) {

        /* create user with random card secret stored on the card */
        int balance;
        char card_name[256];
        FILE *card;
        unsigned char secret[SECRET_SIZE];
        char secret_hex[SECRET_HEX_SIZE];
        User *user;

        if (argc != 4 || !valid_name(argv[1]) || !valid_pin(argv[2]) || !parse_amount(argv[3], &balance)) {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }

        if (find_user(bank, argv[1]) != NULL) {
            printf("Error:  user %s already exists\n", argv[1]);
            return;
        }
        if (bank->num_users >= BANK_MAX_USERS) {
            printf("Error creating card file for user %s\n", argv[1]);
            return;
        }

        sprintf(card_name, "%s.card", argv[1]);
        card = fopen(card_name, "r");
        if (card != NULL) {
            fclose(card);
            printf("Error creating card file for user %s\n", argv[1]);
            return;
        }

        if (!rand_bytes(secret, SECRET_SIZE)) {
            printf("Error creating card file for user %s\n", argv[1]);
            return;
        }
        to_hex(secret, SECRET_SIZE, secret_hex);

        card = fopen(card_name, "w");
        if (card == NULL) {
            printf("Error creating card file for user %s\n", argv[1]);
            return;
        }
        fprintf(card, "%s\n", secret_hex);
        fclose(card);

        user = &bank->users[bank->num_users];
        strcpy(user->name, argv[1]);
        strcpy(user->pin, argv[2]);
        memcpy(user->card_secret, secret, SECRET_SIZE);
        user->balance = balance;
        bank->num_users++;

        printf("Created user %s\n", argv[1]);
        return;
    }

    if (strcmp(argv[0], "deposit") == 0) {

        /* add money to account */
        int amount;
        User *user;

        if (argc != 3 || !valid_name(argv[1]) || !parse_amount(argv[2], &amount)) {
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }

        user = find_user(bank, argv[1]);
        if (user == NULL) {
            printf("No such user\n");
            return;
        }

        if (amount > INT_MAX - user->balance) {
            printf("Too rich for this program\n");
            return;
        }

        user->balance += amount;
        printf("$%d added to %s's account\n", amount, argv[1]);
        return;
    }

    if (strcmp(argv[0], "balance") == 0) {

        /* print account balance */
        User *user;

        if (argc != 2 || !valid_name(argv[1])) {
            printf("Usage:  balance <user-name>\n");
            return;
        }

        user = find_user(bank, argv[1]);
        if (user == NULL) {
            printf("No such user\n");
            return;
        }
        printf("$%d\n", user->balance);
        return;
    }

    printf("Invalid command\n");
}

/* dispatches a decrypted ATM request and writes the plaintext reply */
static void handle_request(Bank *bank, char *plain, char *reply, size_t reply_size) {

    char *argv[4];
    int argc;
    User *user;

    argc = split(plain, argv, 4);

    if (argc == 2 && strcmp(argv[0], "exists") == 0) {

        if (find_user(bank, argv[1]) == NULL) {
            strcpy(reply, "NO");
            return;
        }
        strcpy(reply, "OK");
        return;
    }

    if (argc == 4 && strcmp(argv[0], "auth") == 0) {

        /* both the user-typed pin and the card secret must match */
        unsigned char given[SECRET_SIZE];

        user = find_user(bank, argv[1]);
        if (user == NULL) {
            strcpy(reply, "NO");
            return;
        }
        if (strcmp(user->pin, argv[2]) != 0) {
            strcpy(reply, "NO");
            return;
        }
        if (!from_hex(argv[3], given, SECRET_SIZE)) {
            strcpy(reply, "NO");
            return;
        }
        if (memcmp(user->card_secret, given, SECRET_SIZE) != 0) {
            strcpy(reply, "NO");
            return;
        }
        strcpy(reply, "OK");
        return;
    }

    if (argc == 2 && strcmp(argv[0], "balance") == 0) {

        user = find_user(bank, argv[1]);
        if (user == NULL) {
            strcpy(reply, "NO");
            return;
        }
        snprintf(reply, reply_size, "BAL %d", user->balance);
        return;
    }

    if (argc == 3 && strcmp(argv[0], "withdraw") == 0) {

        int amount;

        user = find_user(bank, argv[1]);
        if (user == NULL || !parse_amount(argv[2], &amount)) {
            strcpy(reply, "NO");
            return;
        }
        if (amount > user->balance) {
            strcpy(reply, "NSF");
            return;
        }
        user->balance -= amount;
        strcpy(reply, "OK");
        return;
    }

    strcpy(reply, "NO");
}

void bank_process_remote_command(Bank *bank, char *command, size_t len) {

    unsigned char plain_buf[1024];
    char plain[1024];
    char reply[256];
    char wire_plain[1024];
    unsigned char wire[1024];
    int plen;
    int wlen;
    char nonce_hex[2 * BANK_NONCE_BYTES + 1];
    unsigned char nonce[BANK_NONCE_BYTES];
    int header_len = 2 + 2 * BANK_NONCE_BYTES + 1;

    /* drop anything that fails authentication or doesn't fit */
    plen = aead_open(bank->key, (unsigned char *)command, len, plain_buf);
    if (plen <= 0 || plen >= (int)sizeof(plain)) {
        return;
    }
    memcpy(plain, plain_buf, plen);
    plain[plen] = '\0';

    /* expected plaintext: "R <nonce_hex> <command...>" */
    if (plen < header_len || plain[0] != 'R' || plain[1] != ' ' || plain[header_len - 1] != ' ') {
        return;
    }
    memcpy(nonce_hex, plain + 2, 2 * BANK_NONCE_BYTES);
    nonce_hex[2 * BANK_NONCE_BYTES] = '\0';
    if (!from_hex(nonce_hex, nonce, BANK_NONCE_BYTES)) {
        return;
    }

    /* drop replays of previously accepted requests */
    if (nonce_seen(bank, nonce)) {
        return;
    }
    nonce_remember(bank, nonce);

    handle_request(bank, plain + header_len, reply, sizeof(reply));

    /* respond with "A <nonce_hex> <reply>" so atm can match and reject reflections */
    snprintf(wire_plain, sizeof(wire_plain), "A %s %s", nonce_hex, reply);
    wlen = aead_seal(bank->key, (unsigned char *)wire_plain, strlen(wire_plain), wire);
    if (wlen < 0) {
        return;
    }
    bank_send(bank, (char *)wire, wlen);
}
