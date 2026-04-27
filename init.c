#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto.h"

/* appends filetype suffix */
static char *add_suffix(const char *name, const char *suffix) {
    char *buf = malloc(strlen(name) + strlen(suffix) + 1);
    if (buf == NULL) return NULL;
    sprintf(buf, "%s%s", name, suffix);
    return buf;
}

/* creates bank and atm initialization files holding a shared AES-GCM key */
int main(int argc, char **argv) {

    char *bank_file, *atm_file;
    FILE *bank, *atm;
    unsigned char key[KEY_SIZE];
    char key_hex[2 * KEY_SIZE + 1];

    if (argc != 2) {
        printf("Usage:  init <filename>");
        return 62;
    }

    bank_file = add_suffix(argv[1], ".bank");
    atm_file = add_suffix(argv[1], ".atm");
    if (bank_file == NULL || atm_file == NULL) {
        free(bank_file); free(atm_file);
        printf("Error creating initialization files");
        return 64;
    }

    if (access(bank_file, F_OK) == 0 || access(atm_file, F_OK) == 0) {
        free(bank_file); free(atm_file);
        printf("Error: one of the files already exists");
        return 63;
    }

    /* freshly generated key shared by bank and atm only */
    if (!rand_bytes(key, KEY_SIZE)) {
        free(bank_file); free(atm_file);
        printf("Error creating initialization files");
        return 64;
    }
    to_hex(key, KEY_SIZE, key_hex);

    bank = fopen(bank_file, "w");
    atm = fopen(atm_file, "w");
    if (bank == NULL || atm == NULL) {
        if (bank != NULL) fclose(bank);
        if (atm != NULL) fclose(atm);
        free(bank_file); free(atm_file);
        printf("Error creating initialization files");
        return 64;
    }

    fprintf(bank, "%s\n", key_hex);
    fprintf(atm, "%s\n", key_hex);
    fclose(bank); fclose(atm);
    free(bank_file); free(atm_file);
    printf("Successfully initialized bank state");
    return 0;
}
