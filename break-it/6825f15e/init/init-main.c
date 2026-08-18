#include "security.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int create_file_with_key(const char *path, const unsigned char *key)
{
    char key_hex[MASTER_KEY_LEN * 2 + 1];
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    FILE *file;

    // use excl so init does not overwrite old state
    if (fd < 0)
        return -1;

    file = fdopen(fd, "w");
    if (file == NULL)
    {
        close(fd);
        return -1;
    }

    // write the shared key in hex
    bytes_to_hex(key, MASTER_KEY_LEN, key_hex);
    if (fprintf(file, "%s\n", key_hex) < 0)
    {
        fclose(file);
        return -1;
    }

    if (fclose(file) != 0)
        return -1;

    return 0;
}

int main(int argc, char **argv)
{
    char bank_path[4096];
    char atm_path[4096];
    unsigned char shared_key[MASTER_KEY_LEN];

    // init takes one base filename
    if (argc != 2)
    {
        printf("Usage:  init <filename>\n");
        return 62;
    }

    // build the .bank and .atm paths
    if (snprintf(bank_path, sizeof(bank_path), "%s.bank", argv[1]) >= (int) sizeof(bank_path) ||
        snprintf(atm_path, sizeof(atm_path), "%s.atm", argv[1]) >= (int) sizeof(atm_path))
    {
        printf("Error creating initialization files\n");
        return 64;
    }

    // init should fail if either target already exists
    if (access(bank_path, F_OK) == 0 || access(atm_path, F_OK) == 0)
    {
        printf("Error: one of the files already exists\n");
        return 63;
    }

    // make one shared key for both files
    if (!random_bytes_secure(shared_key, sizeof(shared_key)) ||
        create_file_with_key(bank_path, shared_key) != 0 ||
        create_file_with_key(atm_path, shared_key) != 0)
    {
        printf("Error creating initialization files\n");
        return 64;
    }

    printf("Successfully initialized bank state\n");
    return 0;
}
