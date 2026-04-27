#include <stdio.h>
#include <stdlib.h>
#include "atm.h"

int main(int argc, char **argv) {

    char user_input[1000];
    ATM *atm;

    /* require a readable init file */
    if (argc != 2) {
        printf("Error opening ATM initialization file\n");
        return 64;
    }

    atm = atm_create();
    if (!atm_load_key(atm, argv[1])) {

        atm_free(atm);
        printf("Error opening ATM initialization file\n");
        return 64;
    }

    if (atm->logged_in) {
        printf("ATM (%s):  ", atm->current_user);
    }
    else {
        printf("ATM: ");
    }
    fflush(stdout);

    /* process commands until stdin is done */
    while (fgets(user_input, sizeof(user_input), stdin) != NULL) {
        atm_process_command(atm, user_input);
        if (atm->logged_in) {
            printf("ATM (%s):  ", atm->current_user);
        }
        else {
            printf("ATM: ");
        }
        fflush(stdout);
    }

    atm_free(atm);
    return EXIT_SUCCESS;
}
