#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char**argv) {

    int n;
    char sendline[1000];
    char recvline[10000];
    Bank *bank;

    if (argc != 2) {
        printf("Error opening bank initialization file\n");
        return 64;
    }

    bank = bank_create();
    if (!bank_load_key(bank, argv[1])) {
        bank_free(bank);
        printf("Error opening bank initialization file\n");
        return 64;
    }

    printf("%s", prompt);
    fflush(stdout);

    /* wait for commands or atm requests */
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(bank->sockfd, &fds);
        select(bank->sockfd + 1, &fds, NULL, NULL, NULL);

        if (FD_ISSET(0, &fds)) {
            if (fgets(sendline, sizeof(sendline), stdin) == NULL) break;
            bank_process_local_command(bank, sendline, strlen(sendline));
            printf("%s", prompt);
            fflush(stdout);
        }
        else if (FD_ISSET(bank->sockfd, &fds)) {
            n = bank_recv(bank, recvline, 10000);
            bank_process_remote_command(bank, recvline, n);
        }
    }

    bank_free(bank);
    return EXIT_SUCCESS;
}
