/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char user_input[1000];
    FILE *init_file;

    if (argc != 2)
    {
        printf("Error opening ATM initialization file\n");
        return 64;
    }

    init_file = fopen(argv[1], "r");
    if (init_file == NULL)
    {
        printf("Error opening ATM initialization file\n");
        return 64;
    }
    fclose(init_file);

    ATM *atm = atm_create(argv[1]);

    printf("%s", atm_prompt(atm));
    fflush(stdout);

    while (fgets(user_input, sizeof(user_input), stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        printf("%s", atm_prompt(atm));
        fflush(stdout);
    }

    atm_free(atm);
    return EXIT_SUCCESS;
}
