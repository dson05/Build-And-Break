#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto.h"

/* appends filetype suffix */
static char *add_suffix(const char *name, const char *suffix) {

    char *buffer = malloc(strlen(name) + strlen(suffix) + 1);
    if (buffer == NULL) {

        return NULL;
    }
    strcpy(buffer, name);
    strcpy(buffer + strlen(name), suffix);
    return buffer;
}

/* creates bank and atm initialization files holding a shared AES-GCM key */
int main(int argc, char **argv) {

    char *bank_file;
    char *atm_file;
    FILE *bank;
    FILE *atm;
    unsigned char key[KEY_SIZE];
    char key_hex[2 * KEY_SIZE + 1];

    /* require one base filename */
    if (argc != 2) {

        printf("Usage:  init <filename>");
        return 62;
    }

    /* build output filenames */
    bank_file = add_suffix(argv[1], ".bank");
    atm_file = add_suffix(argv[1], ".atm");

    if (bank_file == NULL || atm_file == NULL) {

        free(bank_file);
        free(atm_file);
        printf("Error creating initialization files");
        return 64;
    }

    if (access(bank_file, F_OK) == 0 || access(atm_file, F_OK) == 0) {

        printf("Error: one of the files already exists");
        free(bank_file);
        free(atm_file);
        return 63;
    }

    /* freshly generated key shared by bank and atm only */
    if (!rand_bytes(key, KEY_SIZE)) {

        printf("Error creating initialization files");
        free(bank_file);
        free(atm_file);
        return 64;
    }
    to_hex(key, KEY_SIZE, key_hex);

    bank = fopen(bank_file, "w");
    atm = fopen(atm_file, "w");

    if (bank == NULL || atm == NULL) {

        if (bank != NULL) {
            fclose(bank);
        }
        if (atm != NULL) {
            fclose(atm);
        }

        printf("Error creating initialization files");
        free(bank_file);
        free(atm_file);
        return 64;
    }

    fprintf(bank, "%s\n", key_hex);
    fprintf(atm, "%s\n", key_hex);
    fclose(bank);
    fclose(atm);
    free(bank_file);
    free(atm_file);
    printf("Successfully initialized bank state");
    return 0;
}
