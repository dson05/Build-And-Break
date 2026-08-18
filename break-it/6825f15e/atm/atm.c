#include "atm.h"
#include "ports.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

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

    // counters come in as decimal text
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

static int recv_response(ATM *atm, char *buffer, size_t buffer_size)
{
    ssize_t len;

    // leave space for a null terminator
    if (buffer_size == 0)
        return 0;

    len = atm_recv(atm, buffer, buffer_size - 1);
    if (len <= 0)
        return 0;

    buffer[len] = '\0';
    return 1;
}

static int send_request(ATM *atm, const char *request)
{
    return atm_send(atm, (char *) request, strlen(request)) >= 0;
}

static int secure_hex_equal(const char *left, const char *right)
{
    if (left == NULL || right == NULL)
        return 0;
    if (strlen(left) != SHA256_HEX_LEN || strlen(right) != SHA256_HEX_LEN)
        return 0;
    return secure_bytes_equal((const unsigned char *) left, (const unsigned char *) right, SHA256_HEX_LEN);
}

static void trim_newline(char *text)
{
    if (text != NULL)
        text[strcspn(text, "\r\n")] = '\0';
}

static int read_card_file(const char *user_name, unsigned char *card_secret)
{
    char path[512];
    char card_user[256];
    char card_secret_hex[CARD_SECRET_LEN * 2 + 8];
    FILE *card_file;

    // card files live in the current directory
    if (snprintf(path, sizeof(path), "%s.card", user_name) >= (int) sizeof(path))
        return 0;

    card_file = fopen(path, "r");
    if (card_file == NULL)
        return 0;

    if (fgets(card_user, sizeof(card_user), card_file) == NULL ||
        fgets(card_secret_hex, sizeof(card_secret_hex), card_file) == NULL)
    {
        fclose(card_file);
        return 0;
    }

    fclose(card_file);

    trim_newline(card_user);
    trim_newline(card_secret_hex);

    // make sure the card matches the user
    if (strcmp(card_user, user_name) != 0)
        return 0;

    return hex_to_bytes(card_secret_hex, card_secret, CARD_SECRET_LEN);
}

static int user_exists(ATM *atm, const char *user_name)
{
    char nonce_hex[NONCE_LEN * 2 + 1];
    char mac_hex[SHA256_HEX_LEN + 1];
    char request[512];
    char response[512];
    char expected_msg[512];
    char expected_mac[SHA256_HEX_LEN + 1];
    unsigned char nonce[NONCE_LEN];
    char *cmd;
    char *resp_nonce;
    char *resp_mac;

    if (!random_bytes_secure(nonce, sizeof(nonce)))
        return 0;

    // authenticated user existence check
    bytes_to_hex(nonce, sizeof(nonce), nonce_hex);
    if (snprintf(expected_msg, sizeof(expected_msg), "EXISTS|%s|%s", user_name, nonce_hex) >= (int) sizeof(expected_msg) ||
        !hmac_sha256_hex(atm->master_key, sizeof(atm->master_key), expected_msg, mac_hex, sizeof(mac_hex)) ||
        snprintf(request, sizeof(request), "EXISTS %s %s %s", user_name, nonce_hex, mac_hex) >= (int) sizeof(request))
    {
        return 0;
    }

    if (!send_request(atm, request) || !recv_response(atm, response, sizeof(response)))
        return 0;

    cmd = strtok(response, " \t\r\n");
    resp_nonce = strtok(NULL, " \t\r\n");
    resp_mac = strtok(NULL, " \t\r\n");
    if (cmd == NULL || resp_nonce == NULL || resp_mac == NULL || strtok(NULL, " \t\r\n") != NULL)
        return 0;
    if (strcmp(resp_nonce, nonce_hex) != 0)
        return 0;

    if (strcmp(cmd, "EXISTS_OK") == 0)
    {
        if (snprintf(expected_msg, sizeof(expected_msg), "EXISTS_OK|%s|%s", user_name, nonce_hex) >= (int) sizeof(expected_msg) ||
            !hmac_sha256_hex(atm->master_key, sizeof(atm->master_key), expected_msg, expected_mac, sizeof(expected_mac)))
        {
            return 0;
        }
        return secure_hex_equal(resp_mac, expected_mac);
    }

    if (strcmp(cmd, "EXISTS_NO") == 0)
    {
        if (snprintf(expected_msg, sizeof(expected_msg), "EXISTS_NO|%s|%s", user_name, nonce_hex) >= (int) sizeof(expected_msg) ||
            !hmac_sha256_hex(atm->master_key, sizeof(atm->master_key), expected_msg, expected_mac, sizeof(expected_mac)))
        {
            return 0;
        }
        return secure_hex_equal(resp_mac, expected_mac) ? -1 : 0;
    }

    return 0;
}

static int derive_session_key(const ATM *atm, const char *user_name, const char *pin,
                              const unsigned char *card_secret, const char *client_nonce_hex,
                              const char *server_nonce_hex, unsigned char *session_key)
{
    char card_secret_hex[CARD_SECRET_LEN * 2 + 1];
    char message[1024];

    // both nonces keep each session key fresh
    bytes_to_hex(card_secret, CARD_SECRET_LEN, card_secret_hex);
    if (snprintf(message, sizeof(message), "SESSION|%s|%s|%s|%s|%s",
                 user_name, pin, card_secret_hex, client_nonce_hex, server_nonce_hex) >= (int) sizeof(message))
    {
        return 0;
    }

    return hmac_sha256_bytes(atm->master_key, sizeof(atm->master_key), message,
                             session_key, SESSION_KEY_LEN);
}

static void clear_session(ATM *atm)
{
    // clear live session state
    atm->logged_in = 0;
    atm->current_user[0] = '\0';
    memset(atm->current_card_secret, 0, sizeof(atm->current_card_secret));
    memset(atm->session_key, 0, sizeof(atm->session_key));
    atm->next_counter = 1;
}

static int send_session_request(ATM *atm, const char *verb, const char *arg,
                                char *response, size_t response_size)
{
    char mac_message[128];
    char mac_hex[SHA256_HEX_LEN + 1];
    char request[512];

    if (arg == NULL)
    {
        if (snprintf(mac_message, sizeof(mac_message), "%s|%u", verb, atm->next_counter) >= (int) sizeof(mac_message) ||
            !hmac_sha256_hex(atm->session_key, sizeof(atm->session_key), mac_message, mac_hex, sizeof(mac_hex)) ||
            snprintf(request, sizeof(request), "%s %u %s", verb, atm->next_counter, mac_hex) >= (int) sizeof(request))
        {
            return 0;
        }
    }
    else
    {
        if (snprintf(mac_message, sizeof(mac_message), "%s|%s|%u", verb, arg, atm->next_counter) >= (int) sizeof(mac_message) ||
            !hmac_sha256_hex(atm->session_key, sizeof(atm->session_key), mac_message, mac_hex, sizeof(mac_hex)) ||
            snprintf(request, sizeof(request), "%s %s %u %s", verb, arg, atm->next_counter, mac_hex) >= (int) sizeof(request))
        {
            return 0;
        }
    }

    if (!send_request(atm, request) || !recv_response(atm, response, response_size))
        return 0;

    // include the next counter in every session request
    return 1;
}

static int verify_balance_response(ATM *atm, const char *amount_text, const char *counter_text,
                                   const char *mac_hex)
{
    char expected_message[128];
    char expected_mac[SHA256_HEX_LEN + 1];
    unsigned int counter;

    // response must match the current counter
    if (amount_text == NULL || counter_text == NULL || mac_hex == NULL)
        return 0;
    if (!parse_counter(counter_text, &counter) || counter != atm->next_counter)
        return 0;
    if (snprintf(expected_message, sizeof(expected_message), "BALANCE|%s|%u", amount_text, counter) >= (int) sizeof(expected_message) ||
        !hmac_sha256_hex(atm->session_key, sizeof(atm->session_key), expected_message, expected_mac, sizeof(expected_mac)))
    {
        return 0;
    }

    return secure_hex_equal(mac_hex, expected_mac);
}

static int verify_withdraw_response(ATM *atm, const char *verb, const char *amount_text,
                                    const char *counter_text, const char *mac_hex)
{
    char expected_message[128];
    char expected_mac[SHA256_HEX_LEN + 1];
    unsigned int counter;

    // same check for withdraw-style replies
    if (counter_text == NULL || mac_hex == NULL)
        return 0;
    if (!parse_counter(counter_text, &counter) || counter != atm->next_counter)
        return 0;
    if (amount_text == NULL)
    {
        if (snprintf(expected_message, sizeof(expected_message), "%s|%u", verb, counter) >= (int) sizeof(expected_message))
            return 0;
    }
    else
    {
        if (snprintf(expected_message, sizeof(expected_message), "%s|%s|%u", verb, amount_text, counter) >= (int) sizeof(expected_message))
            return 0;
    }

    if (!hmac_sha256_hex(atm->session_key, sizeof(atm->session_key), expected_message, expected_mac, sizeof(expected_mac)))
        return 0;

    return secure_hex_equal(mac_hex, expected_mac);
}

static void handle_begin_session(ATM *atm, char *user_name, char *extra)
{
    char pin[64];
    char request[512];
    char response[512];
    char client_nonce_hex[NONCE_LEN * 2 + 1];
    char server_nonce_hex[NONCE_LEN * 2 + 1];
    char card_secret_hex[CARD_SECRET_LEN * 2 + 1];
    char auth_message[1024];
    char auth_mac[SHA256_HEX_LEN + 1];
    char expected_message[1024];
    char expected_mac[SHA256_HEX_LEN + 1];
    unsigned char client_nonce[NONCE_LEN];
    unsigned char card_secret[CARD_SECRET_LEN];
    char *cmd;
    char *resp_nonce;
    char *resp_mac;
    int exists_result;

    // only one user can be logged in
    if (atm->logged_in)
    {
        printf("A user is already logged in\n");
        return;
    }

    if (user_name == NULL || extra != NULL || !is_valid_username(user_name))
    {
        printf("Usage: begin-session <user-name>\n");
        return;
    }

    // check with the bank before touching the card
    exists_result = user_exists(atm, user_name);
    if (exists_result < 0)
    {
        printf("No such user\n");
        return;
    }
    if (exists_result == 0)
    {
        printf("Not authorized\n");
        return;
    }

    // login needs both the card and the pin
    if (!read_card_file(user_name, card_secret))
    {
        printf("Unable to access %s's card\n", user_name);
        return;
    }

    printf("PIN? ");
    fflush(stdout);
    if (fgets(pin, sizeof(pin), stdin) == NULL)
    {
        printf("Not authorized\n");
        return;
    }

    trim_newline(pin);
    if (!is_valid_pin(pin) || !random_bytes_secure(client_nonce, sizeof(client_nonce)))
    {
        printf("Not authorized\n");
        return;
    }

    bytes_to_hex(client_nonce, sizeof(client_nonce), client_nonce_hex);
    bytes_to_hex(card_secret, sizeof(card_secret), card_secret_hex);
    if (snprintf(auth_message, sizeof(auth_message), "AUTH|%s|%s|%s|%s",
                 user_name, pin, card_secret_hex, client_nonce_hex) >= (int) sizeof(auth_message) ||
        !hmac_sha256_hex(atm->master_key, sizeof(atm->master_key), auth_message, auth_mac, sizeof(auth_mac)) ||
        snprintf(request, sizeof(request), "AUTH %s %s %s", user_name, client_nonce_hex, auth_mac) >= (int) sizeof(request))
    {
        printf("Not authorized\n");
        return;
    }

    if (!send_request(atm, request) || !recv_response(atm, response, sizeof(response)))
    {
        printf("Not authorized\n");
        return;
    }

    cmd = strtok(response, " \t\r\n");
    resp_nonce = strtok(NULL, " \t\r\n");
    resp_mac = strtok(NULL, " \t\r\n");
    if (cmd == NULL || resp_nonce == NULL || resp_mac == NULL || strtok(NULL, " \t\r\n") != NULL)
    {
        printf("Not authorized\n");
        return;
    }

    if (strcmp(cmd, "AUTH_FAIL") == 0)
    {
        printf("Not authorized\n");
        return;
    }

    if (strcmp(cmd, "AUTH_OK") != 0)
    {
        printf("Not authorized\n");
        return;
    }

    if (strlen(resp_nonce) != NONCE_LEN * 2)
    {
        printf("Not authorized\n");
        return;
    }

    strncpy(server_nonce_hex, resp_nonce, sizeof(server_nonce_hex));
    server_nonce_hex[sizeof(server_nonce_hex) - 1] = '\0';
    if (snprintf(expected_message, sizeof(expected_message), "AUTH_OK|%s|%s|%s|%s|%s",
                 user_name, pin, card_secret_hex, client_nonce_hex, server_nonce_hex) >= (int) sizeof(expected_message) ||
        !hmac_sha256_hex(atm->master_key, sizeof(atm->master_key), expected_message, expected_mac, sizeof(expected_mac)) ||
        !secure_hex_equal(resp_mac, expected_mac) ||
        !derive_session_key(atm, user_name, pin, card_secret, client_nonce_hex, server_nonce_hex, atm->session_key))
    {
        printf("Not authorized\n");
        return;
    }

    atm->logged_in = 1;
    strcpy(atm->current_user, user_name);
    memcpy(atm->current_card_secret, card_secret, sizeof(card_secret));
    atm->next_counter = 1;
    printf("Authorized\n");
}

static void handle_balance(ATM *atm, char *extra)
{
    char response[512];
    char *cmd;
    char *amount_text;
    char *counter_text;
    char *mac_hex;

    if (!atm->logged_in)
    {
        printf("No user logged in\n");
        return;
    }

    if (extra != NULL)
    {
        printf("Usage: balance\n");
        return;
    }

    // bad replies kill the session
    if (!send_session_request(atm, "BALANCE", NULL, response, sizeof(response)))
    {
        clear_session(atm);
        printf("No user logged in\n");
        return;
    }

    cmd = strtok(response, " \t\r\n");
    amount_text = strtok(NULL, " \t\r\n");
    counter_text = strtok(NULL, " \t\r\n");
    mac_hex = strtok(NULL, " \t\r\n");
    if (cmd == NULL || strcmp(cmd, "BALANCE") != 0 || strtok(NULL, " \t\r\n") != NULL ||
        !verify_balance_response(atm, amount_text, counter_text, mac_hex))
    {
        clear_session(atm);
        printf("No user logged in\n");
        return;
    }

    atm->next_counter++;
    printf("$%s\n", amount_text);
}

static void handle_withdraw(ATM *atm, char *amount_text, char *extra)
{
    char response[512];
    char amount_arg[32];
    int amount;
    char *cmd;
    char *token1;
    char *token2;
    char *token3;

    // bad replies kill the session here too
    if (!atm->logged_in)
    {
        printf("No user logged in\n");
        return;
    }

    if (amount_text == NULL || extra != NULL || !parse_nonnegative_int(amount_text, &amount))
    {
        printf("Usage: withdraw <amt>\n");
        return;
    }

    snprintf(amount_arg, sizeof(amount_arg), "%d", amount);
    if (!send_session_request(atm, "WITHDRAW", amount_arg, response, sizeof(response)))
    {
        clear_session(atm);
        printf("Insufficient funds\n");
        return;
    }

    cmd = strtok(response, " \t\r\n");
    token1 = strtok(NULL, " \t\r\n");
    token2 = strtok(NULL, " \t\r\n");
    token3 = strtok(NULL, " \t\r\n");

    if (cmd == NULL)
    {
        clear_session(atm);
        printf("Insufficient funds\n");
        return;
    }

    if (strcmp(cmd, "DISPENSE") == 0)
    {
        if (token1 == NULL || token2 == NULL || token3 == NULL || strtok(NULL, " \t\r\n") != NULL ||
            !verify_withdraw_response(atm, "DISPENSE", token1, token2, token3))
        {
            clear_session(atm);
            printf("Insufficient funds\n");
            return;
        }

        atm->next_counter++;
        printf("$%s dispensed\n", token1);
        return;
    }

    if (strcmp(cmd, "INSUFFICIENT") == 0)
    {
        if (token1 == NULL || token2 == NULL || token3 != NULL || strtok(NULL, " \t\r\n") != NULL ||
            !verify_withdraw_response(atm, "INSUFFICIENT", NULL, token1, token2))
        {
            clear_session(atm);
        }
        else
        {
            atm->next_counter++;
        }
        printf("Insufficient funds\n");
        return;
    }

    clear_session(atm);
    printf("Insufficient funds\n");
}

static void handle_end_session(ATM *atm, char *extra)
{
    char response[512];
    char *cmd;
    char *counter_text;
    char *mac_hex;

    if (!atm->logged_in)
    {
        printf("No user logged in\n");
        return;
    }

    if (extra != NULL)
    {
        printf("Invalid command\n");
        return;
    }

    if (send_session_request(atm, "END", NULL, response, sizeof(response)))
    {
        cmd = strtok(response, " \t\r\n");
        counter_text = strtok(NULL, " \t\r\n");
        mac_hex = strtok(NULL, " \t\r\n");
        // still log out locally if the reply looks weird
        if (cmd != NULL && strcmp(cmd, "END_OK") == 0 && strtok(NULL, " \t\r\n") == NULL &&
            verify_withdraw_response(atm, "END_OK", NULL, counter_text, mac_hex))
        {
            atm->next_counter++;
        }
    }

    clear_session(atm);
    printf("User logged out\n");
}

ATM* atm_create(const char *init_path)
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // no init key means no protocol
    if (!load_master_key(init_path, atm->master_key))
    {
        free(atm);
        perror("Could not load ATM initialization data");
        exit(1);
    }

    // shared key from init
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);
    if (atm->sockfd < 0)
    {
        perror("Could not create ATM socket");
        free(atm);
        exit(1);
    }

    {
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(atm->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    if (bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr)) < 0)
    {
        perror("Could not bind ATM socket");
        close(atm->sockfd);
        free(atm);
        exit(1);
    }

    clear_session(atm);
    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command)
{
    char *cmd;
    char *arg1;
    char *arg2;

    cmd = strtok(command, " \t\r\n");
    if (cmd == NULL)
    {
        printf("Invalid command\n");
        return;
    }

    arg1 = strtok(NULL, " \t\r\n");
    arg2 = strtok(NULL, " \t\r\n");

    if (strcmp(cmd, "begin-session") == 0)
        handle_begin_session(atm, arg1, arg2);
    else if (strcmp(cmd, "balance") == 0)
        handle_balance(atm, arg1);
    else if (strcmp(cmd, "withdraw") == 0)
        handle_withdraw(atm, arg1, arg2);
    else if (strcmp(cmd, "end-session") == 0)
        handle_end_session(atm, arg1);
    else
        printf("Invalid command\n");
}

const char *atm_prompt(ATM *atm)
{
    static char prompt[300];

    if (atm != NULL && atm->logged_in)
    {
        snprintf(prompt, sizeof(prompt), "ATM (%s):  ", atm->current_user);
        return prompt;
    }

    return "ATM: ";
}
