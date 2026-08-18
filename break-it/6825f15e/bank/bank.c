#include "bank.h"
#include "ports.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bank_user *find_user(Bank *bank, const char *name)
{
    bank_user *user = bank->users;

    while (user != NULL)
    {
        if (strcmp(user->name, name) == 0)
            return user;
        user = user->next;
    }

    return NULL;
}

static bank_user *find_active_user(Bank *bank)
{
    bank_user *user = bank->users;

    // only one active session matters here
    while (user != NULL)
    {
        if (user->session_active)
            return user;
        user = user->next;
    }

    return NULL;
}

static void clear_all_sessions(Bank *bank)
{
    bank_user *user = bank->users;

    while (user != NULL)
    {
        // clear any live session state
        user->session_active = 0;
        memset(user->session_key, 0, sizeof(user->session_key));
        user->last_counter = 0;
        user = user->next;
    }
}

static int is_valid_username(const char *name)
{
    size_t i;
    size_t len;

    if (name == NULL)
        return 0;

    len = strlen(name);
    if (len == 0 || len > 250)
        return 0;

    for (i = 0; i < len; i++)
    {
        if (!isalpha((unsigned char) name[i]))
            return 0;
    }

    return 1;
}

static int is_valid_pin(const char *pin)
{
    size_t i;

    if (pin == NULL || strlen(pin) != 4)
        return 0;

    for (i = 0; i < 4; i++)
    {
        if (!isdigit((unsigned char) pin[i]))
            return 0;
    }

    return 1;
}

static int parse_nonnegative_int(const char *text, int *value)
{
    char *endptr;
    long parsed;

    if (text == NULL || text[0] == '\0')
        return 0;

    errno = 0;
    parsed = strtol(text, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || parsed < 0 || parsed > INT_MAX)
        return 0;

    *value = (int) parsed;
    return 1;
}

static int parse_counter(const char *text, unsigned int *value)
{
    char *endptr;
    unsigned long parsed;

    // counters come in as decimal text here too
    if (text == NULL || text[0] == '\0')
        return 0;

    errno = 0;
    parsed = strtoul(text, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || parsed > UINT_MAX)
        return 0;

    *value = (unsigned int) parsed;
    return 1;
}

static int load_master_key(const char *path, unsigned char *key)
{
    char line[128];
    FILE *file = fopen(path, "r");

    // the init file is just one key line
    if (file == NULL)
        return 0;

    if (fgets(line, sizeof(line), file) == NULL)
    {
        fclose(file);
        return 0;
    }

    fclose(file);
    line[strcspn(line, "\r\n")] = '\0';
    return hex_to_bytes(line, key, MASTER_KEY_LEN);
}

static int write_card_path(const char *path, const char *user_name, const unsigned char *card_secret)
{
    char card_secret_hex[CARD_SECRET_LEN * 2 + 1];
    FILE *card_file;

    card_file = fopen(path, "w");
    if (card_file == NULL)
        return 0;

    bytes_to_hex(card_secret, CARD_SECRET_LEN, card_secret_hex);
    if (fprintf(card_file, "%s\n%s\n", user_name, card_secret_hex) < 0)
    {
        fclose(card_file);
        return 0;
    }

    if (fclose(card_file) != 0)
        return 0;

    return 1;
}

static int secure_hex_equal(const char *left, const char *right)
{
    if (left == NULL || right == NULL)
        return 0;
    if (strlen(left) != SHA256_HEX_LEN || strlen(right) != SHA256_HEX_LEN)
        return 0;
    return secure_bytes_equal((const unsigned char *) left, (const unsigned char *) right, SHA256_HEX_LEN);
}

static int create_card_file(const char *user_name, const unsigned char *card_secret)
{
    char path[512];

    if (snprintf(path, sizeof(path), "%s.card", user_name) >= (int) sizeof(path))
        return 0;

    return write_card_path(path, user_name, card_secret);
}

static void add_user(Bank *bank, bank_user *user)
{
    user->next = bank->users;
    bank->users = user;
}

static void remove_user(Bank *bank, bank_user *user)
{
    bank_user *curr = bank->users;
    bank_user *prev = NULL;

    while (curr != NULL)
    {
        if (curr == user)
        {
            if (prev == NULL)
                bank->users = curr->next;
            else
                prev->next = curr->next;
            return;
        }

        prev = curr;
        curr = curr->next;
    }
}

static bank_user *make_user(const char *name, const char *pin, int balance,
                            const unsigned char *card_secret)
{
    bank_user *user = malloc(sizeof(bank_user));

    // keep user state in memory for this run
    if (user == NULL)
        return NULL;

    user->name = strdup(name);
    if (user->name == NULL)
    {
        free(user);
        return NULL;
    }

    strcpy(user->pin, pin);
    user->balance = balance;
    memcpy(user->card_secret, card_secret, CARD_SECRET_LEN);
    user->session_active = 0;
    memset(user->session_key, 0, sizeof(user->session_key));
    user->last_counter = 0;
    user->next = NULL;
    return user;
}

static void free_user(bank_user *user)
{
    if (user == NULL)
        return;

    free(user->name);
    free(user);
}

static int derive_session_key(Bank *bank, const bank_user *user, const char *client_nonce_hex,
                              const char *server_nonce_hex, unsigned char *session_key)
{
    char card_secret_hex[CARD_SECRET_LEN * 2 + 1];
    char message[1024];

    // derive the same session key as the atm
    bytes_to_hex(user->card_secret, CARD_SECRET_LEN, card_secret_hex);
    if (snprintf(message, sizeof(message), "SESSION|%s|%s|%s|%s|%s",
                 user->name, user->pin, card_secret_hex, client_nonce_hex, server_nonce_hex) >= (int) sizeof(message))
    {
        return 0;
    }

    return hmac_sha256_bytes(bank->master_key, sizeof(bank->master_key), message,
                             session_key, SESSION_KEY_LEN);
}

static void process_create_user(Bank *bank, char *user_name, char *pin, char *balance_text, char *extra)
{
    int balance;
    bank_user *user;
    unsigned char card_secret[CARD_SECRET_LEN];

    if (user_name == NULL || pin == NULL || balance_text == NULL || extra != NULL ||
        !is_valid_username(user_name) || !is_valid_pin(pin) ||
        !parse_nonnegative_int(balance_text, &balance))
    {
        printf("Usage:  create-user <user-name> <pin> <balance>\n");
        return;
    }

    if (find_user(bank, user_name) != NULL)
    {
        printf("Error:  user %s already exists\n", user_name);
        return;
    }

    if (!random_bytes_secure(card_secret, sizeof(card_secret)))
    {
        printf("Error creating card file for user %s\n", user_name);
        return;
    }

    // each card gets its own secret
    user = make_user(user_name, pin, balance, card_secret);
    if (user == NULL)
    {
        printf("Error creating card file for user %s\n", user_name);
        return;
    }

    add_user(bank, user);

    if (!create_card_file(user_name, card_secret))
    {
        remove_user(bank, user);
        free_user(user);
        printf("Error creating card file for user %s\n", user_name);
        return;
    }

    printf("Created user %s\n", user_name);
}

static void process_deposit(Bank *bank, char *user_name, char *amount_text, char *extra)
{
    int amount;
    bank_user *user;

    if (user_name == NULL || amount_text == NULL || extra != NULL ||
        !is_valid_username(user_name) || !parse_nonnegative_int(amount_text, &amount))
    {
        printf("Usage:  deposit <user-name> <amt>\n");
        return;
    }

    user = find_user(bank, user_name);
    if (user == NULL)
    {
        printf("No such user\n");
        return;
    }

    if (user->balance > INT_MAX - amount)
    {
        printf("Too rich for this program\n");
        return;
    }

    user->balance += amount;
    printf("$%d added to %s's account\n", amount, user_name);
}

static void process_balance(Bank *bank, char *user_name, char *extra)
{
    bank_user *user;

    if (user_name == NULL || extra != NULL || !is_valid_username(user_name))
    {
        printf("Usage:  balance <user-name>\n");
        return;
    }

    user = find_user(bank, user_name);
    if (user == NULL)
    {
        printf("No such user\n");
        return;
    }

    printf("$%d\n", user->balance);
}

static void send_response(Bank *bank, const char *response)
{
    bank_send(bank, (char *) response, strlen(response));
}

static void send_exists_response(Bank *bank, const char *kind, const char *user_name, const char *nonce_hex)
{
    char mac_message[512];
    char mac_hex[SHA256_HEX_LEN + 1];
    char response[512];

    if (snprintf(mac_message, sizeof(mac_message), "%s|%s|%s", kind, user_name, nonce_hex) >= (int) sizeof(mac_message) ||
        !hmac_sha256_hex(bank->master_key, sizeof(bank->master_key), mac_message, mac_hex, sizeof(mac_hex)) ||
        snprintf(response, sizeof(response), "%s %s %s", kind, nonce_hex, mac_hex) >= (int) sizeof(response))
    {
        send_response(bank, "ERROR");
        return;
    }

    send_response(bank, response);
}

static int verify_session_mac(const bank_user *user, const char *message, const char *mac_hex)
{
    char expected_mac[SHA256_HEX_LEN + 1];

    // shared mac check for session traffic
    if (!hmac_sha256_hex(user->session_key, sizeof(user->session_key), message, expected_mac, sizeof(expected_mac)))
        return 0;

    return secure_hex_equal(mac_hex, expected_mac);
}

Bank* bank_create(const char *init_path)
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // no init key means no protocol
    if (!load_master_key(init_path, bank->master_key))
    {
        free(bank);
        perror("Could not load bank initialization data");
        exit(1);
    }

    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);
    if (bank->sockfd < 0)
    {
        perror("Could not create bank socket");
        free(bank);
        exit(1);
    }

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    if (bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr)) < 0)
    {
        perror("Could not bind bank socket");
        close(bank->sockfd);
        free(bank);
        exit(1);
    }

    bank->users = NULL;

    return bank;
}

void bank_free(Bank *bank)
{
    bank_user *user;
    bank_user *next;

    if(bank != NULL)
    {
        user = bank->users;
        while (user != NULL)
        {
            next = user->next;
            free_user(user);
            user = next;
        }

        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    char *cmd;
    char *arg1;
    char *arg2;
    char *arg3;
    char *arg4;

    (void) len;

    cmd = strtok(command, " \t\r\n");
    if (cmd == NULL)
    {
        printf("Invalid command\n");
        return;
    }

    arg1 = strtok(NULL, " \t\r\n");
    arg2 = strtok(NULL, " \t\r\n");
    arg3 = strtok(NULL, " \t\r\n");
    arg4 = strtok(NULL, " \t\r\n");

    if (strcmp(cmd, "create-user") == 0)
        process_create_user(bank, arg1, arg2, arg3, arg4);
    else if (strcmp(cmd, "deposit") == 0)
        process_deposit(bank, arg1, arg2, arg3);
    else if (strcmp(cmd, "balance") == 0)
        process_balance(bank, arg1, arg2);
    else
        printf("Invalid command\n");
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    char *cmd;
    char *arg1;
    char *arg2;
    char *arg3;
    char *extra;
    char response[1024];
    char expected_message[1024];
    char expected_mac[SHA256_HEX_LEN + 1];
    char card_secret_hex[CARD_SECRET_LEN * 2 + 1];
    char server_nonce_hex[NONCE_LEN * 2 + 1];
    unsigned char server_nonce[NONCE_LEN];
    unsigned char session_key[SESSION_KEY_LEN];
    bank_user *user;
    unsigned int counter;
    int amount;

    if (len <= 0)
        return;

    command[len] = '\0';

    cmd = strtok(command, " \t\r\n");
    if (cmd == NULL)
    {
        send_response(bank, "ERROR");
        return;
    }

    arg1 = strtok(NULL, " \t\r\n");
    arg2 = strtok(NULL, " \t\r\n");
    arg3 = strtok(NULL, " \t\r\n");
    extra = strtok(NULL, " \t\r\n");

    if (strcmp(cmd, "EXISTS") == 0)
    {
        // even the existence check is authenticated
        if (arg1 == NULL || arg2 == NULL || arg3 == NULL || extra != NULL ||
            !is_valid_username(arg1) || strlen(arg2) != NONCE_LEN * 2 ||
            snprintf(expected_message, sizeof(expected_message), "EXISTS|%s|%s", arg1, arg2) >= (int) sizeof(expected_message) ||
            !hmac_sha256_hex(bank->master_key, sizeof(bank->master_key), expected_message, expected_mac, sizeof(expected_mac)) ||
            !secure_hex_equal(arg3, expected_mac))
        {
            send_response(bank, "ERROR");
            return;
        }

        user = find_user(bank, arg1);
        if (user == NULL)
            send_exists_response(bank, "EXISTS_NO", arg1, arg2);
        else
            send_exists_response(bank, "EXISTS_OK", arg1, arg2);
        return;
    }

    if (strcmp(cmd, "AUTH") == 0)
    {
        // login has to prove card and pin
        if (arg1 == NULL || arg2 == NULL || arg3 == NULL || extra != NULL ||
            !is_valid_username(arg1) || strlen(arg2) != NONCE_LEN * 2)
        {
            send_response(bank, "AUTH_FAIL");
            return;
        }

        user = find_user(bank, arg1);
        if (user == NULL)
        {
            send_response(bank, "AUTH_FAIL");
            return;
        }

        bytes_to_hex(user->card_secret, CARD_SECRET_LEN, card_secret_hex);
        if (snprintf(expected_message, sizeof(expected_message), "AUTH|%s|%s|%s|%s",
                     user->name, user->pin, card_secret_hex, arg2) >= (int) sizeof(expected_message) ||
            !hmac_sha256_hex(bank->master_key, sizeof(bank->master_key), expected_message, expected_mac, sizeof(expected_mac)))
        {
            send_response(bank, "AUTH_FAIL");
            return;
        }

        if (!secure_hex_equal(arg3, expected_mac))
        {
            send_response(bank, "AUTH_FAIL");
            return;
        }

        if (!random_bytes_secure(server_nonce, sizeof(server_nonce)))
        {
            send_response(bank, "AUTH_FAIL");
            return;
        }

        bytes_to_hex(server_nonce, sizeof(server_nonce), server_nonce_hex);
        if (snprintf(expected_message, sizeof(expected_message), "AUTH_OK|%s|%s|%s|%s|%s",
                     user->name, user->pin, card_secret_hex, arg2, server_nonce_hex) >= (int) sizeof(expected_message) ||
            !hmac_sha256_hex(bank->master_key, sizeof(bank->master_key), expected_message, expected_mac, sizeof(expected_mac)) ||
            !derive_session_key(bank, user, arg2, server_nonce_hex, session_key) ||
            snprintf(response, sizeof(response), "AUTH_OK %s %s", server_nonce_hex, expected_mac) >= (int) sizeof(response))
        {
            send_response(bank, "AUTH_FAIL");
            return;
        }

        clear_all_sessions(bank);
        user->session_active = 1;
        user->last_counter = 0;
        // store the live session key
        memcpy(user->session_key, session_key, sizeof(session_key));
        send_response(bank, response);
        return;
    }

    // remote commands need a live session
    user = find_active_user(bank);
    if (user == NULL)
    {
        send_response(bank, "ERROR");
        return;
    }

    if (strcmp(cmd, "BALANCE") == 0)
    {
        if (arg1 == NULL || arg2 == NULL || arg3 != NULL || extra != NULL ||
            !parse_counter(arg1, &counter) || counter <= user->last_counter ||
            snprintf(expected_message, sizeof(expected_message), "BALANCE|%u", counter) >= (int) sizeof(expected_message) ||
            !verify_session_mac(user, expected_message, arg2))
        {
            send_response(bank, "ERROR");
            return;
        }

        // counters only move forward
        user->last_counter = counter;
        if (snprintf(expected_message, sizeof(expected_message), "BALANCE|%d|%u", user->balance, counter) >= (int) sizeof(expected_message) ||
            !hmac_sha256_hex(user->session_key, sizeof(user->session_key), expected_message, expected_mac, sizeof(expected_mac)) ||
            snprintf(response, sizeof(response), "BALANCE %d %u %s", user->balance, counter, expected_mac) >= (int) sizeof(response))
        {
            send_response(bank, "ERROR");
            return;
        }

        send_response(bank, response);
        return;
    }

    if (strcmp(cmd, "WITHDRAW") == 0)
    {
        // verify the mac before touching the balance
        if (arg1 == NULL || arg2 == NULL || arg3 == NULL || extra != NULL ||
            !parse_nonnegative_int(arg1, &amount) || !parse_counter(arg2, &counter) ||
            counter <= user->last_counter ||
            snprintf(expected_message, sizeof(expected_message), "WITHDRAW|%d|%u", amount, counter) >= (int) sizeof(expected_message) ||
            !verify_session_mac(user, expected_message, arg3))
        {
            send_response(bank, "ERROR");
            return;
        }

        user->last_counter = counter;
        if (user->balance < amount)
        {
            // even "no" replies are authenticated
            if (snprintf(expected_message, sizeof(expected_message), "INSUFFICIENT|%u", counter) >= (int) sizeof(expected_message) ||
                !hmac_sha256_hex(user->session_key, sizeof(user->session_key), expected_message, expected_mac, sizeof(expected_mac)) ||
                snprintf(response, sizeof(response), "INSUFFICIENT %u %s", counter, expected_mac) >= (int) sizeof(response))
            {
                send_response(bank, "ERROR");
                return;
            }

            send_response(bank, response);
            return;
        }

        user->balance -= amount;
        if (snprintf(expected_message, sizeof(expected_message), "DISPENSE|%d|%u", amount, counter) >= (int) sizeof(expected_message) ||
            !hmac_sha256_hex(user->session_key, sizeof(user->session_key), expected_message, expected_mac, sizeof(expected_mac)) ||
            snprintf(response, sizeof(response), "DISPENSE %d %u %s", amount, counter, expected_mac) >= (int) sizeof(response))
        {
            send_response(bank, "ERROR");
            return;
        }

        send_response(bank, response);
        return;
    }

    if (strcmp(cmd, "END") == 0)
    {
        // ending the session clears the live key
        if (arg1 == NULL || arg2 == NULL || arg3 != NULL || extra != NULL ||
            !parse_counter(arg1, &counter) || counter <= user->last_counter ||
            snprintf(expected_message, sizeof(expected_message), "END|%u", counter) >= (int) sizeof(expected_message) ||
            !verify_session_mac(user, expected_message, arg2))
        {
            send_response(bank, "ERROR");
            return;
        }

        user->last_counter = counter;
        if (snprintf(expected_message, sizeof(expected_message), "END_OK|%u", counter) >= (int) sizeof(expected_message) ||
            !hmac_sha256_hex(user->session_key, sizeof(user->session_key), expected_message, expected_mac, sizeof(expected_mac)) ||
            snprintf(response, sizeof(response), "END_OK %u %s", counter, expected_mac) >= (int) sizeof(response))
        {
            send_response(bank, "ERROR");
            return;
        }

        user->session_active = 0;
        memset(user->session_key, 0, sizeof(user->session_key));
        send_response(bank, response);
        return;
    }

    send_response(bank, "ERROR");
}
