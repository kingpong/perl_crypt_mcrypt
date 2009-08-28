/*
 * generate_testcases.c
 *
 * Generates a list of known-good inputs/outputs to be compared against the
 * output of Crypt::Mcrypt.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mcrypt.h>

typedef enum { PADDING_NONE, PADDING_PKCS7, PADDING_ZEROS } padding_t;
const char *padding_name(padding_t padding);

unsigned char *gen_rand_data(unsigned int len);
char *dump_value(void *buffer, int len);

void dump_list(char **list, int len);
void dump_testcase(char *algo, char *mode);
void dump_testcase_keysize(MCRYPT td, int key_size);
void dump_testcase_block(MCRYPT td, unsigned char *key, int key_size,
                         unsigned char *iv, int iv_size, int block_size,
                         padding_t padding);

int *list_key_sizes(MCRYPT td);

static char testing_algo[128];
static char testing_mode[128];

int main() {
    char **algos, **modes;
    int n_algos, n_modes,
        i_algo,  i_mode;

    /* get consistent output even though it's "random" */
    srand48(1153616166L);

    algos = mcrypt_list_algorithms(NULL, &n_algos);
    if (algos == NULL) {
        fprintf(stderr, "Unable to list algorithms.\n");
        exit(1);
    }

    modes = mcrypt_list_modes(NULL, &n_modes);
    if (modes == NULL) {
        fprintf(stderr, "Unable to list modes.\n");
        exit(1);
    }

    for (i_algo = 0; i_algo < n_algos; i_algo++) {
        for (i_mode = 0; i_mode < n_modes; i_mode++) {
            dump_testcase(algos[i_algo],modes[i_mode]);
        }
    }

    mcrypt_free_p(algos, n_algos);
    mcrypt_free_p(modes, n_modes);

    return 0;
}

void dump_testcase(char *algo, char *mode) {
    MCRYPT td;
    int *key_sizes, *cur_size;

    /* globalize this for easier access below */
    strcpy(testing_algo, algo);
    strcpy(testing_mode, mode);

    td = mcrypt_module_open(algo, NULL, mode, NULL);
    if (td == MCRYPT_FAILED) {
        /* assume that this algorithm just doesn't support this mode */
        return;
    }

    cur_size = key_sizes = list_key_sizes(td);
    if (key_sizes == NULL) {
        return;
    }

    while (*cur_size != 0) {
        dump_testcase_keysize(td, *cur_size);
        cur_size++;
    }

    mcrypt_module_close(td);
}

void dump_testcase_keysize(MCRYPT td, int key_size) {
    unsigned char *key, *iv = NULL;
    int iv_size, block_size;
    int mc_ret;
    padding_t padding;

    key = gen_rand_data(key_size);

    iv_size = mcrypt_enc_get_iv_size(td);
    if (iv_size != 0) {
        iv = gen_rand_data(iv_size);
    }

    /*
     * Generate a test case for these plaintext sizes:
     *
     *  * empty:              test behavior of padding on empty blocks
     *  * 5-byte:             odd, and smaller than any block size
     *  * block_size - 1:     edge case
     *  * block_size:         generally guaranteed to work
     *  * block_size * 2 - 1: multiblock edge case
     *  * block_size * 3:     more multiblock
     */
    block_size = mcrypt_enc_get_block_size(td);

    for (padding = PADDING_NONE; padding <= PADDING_ZEROS; padding++) {
        dump_testcase_block(td, key, key_size, iv, iv_size, 0, padding);
        dump_testcase_block(td, key, key_size, iv, iv_size, 5, padding);
        dump_testcase_block(td, key, key_size, iv, iv_size, block_size - 1,
                            padding);
        dump_testcase_block(td, key, key_size, iv, iv_size, block_size,
                            padding);
        dump_testcase_block(td, key, key_size, iv, iv_size,
                            block_size * 2 - 1, padding);
        dump_testcase_block(td, key, key_size, iv, iv_size, block_size * 3,
                            padding);
    }

    return;
}

void dump_testcase_block(MCRYPT td, unsigned char *key, int key_size,
                         unsigned char *iv, int iv_size, int data_size,
                         padding_t padding) {
    int mc_ret;
    int is_block, block_size, block_overlap, block_fill;
    int i;
    unsigned char *plaintext, *ciphertext;

    mc_ret = mcrypt_generic_init(td, (void *)key, key_size, (void *)iv);
    if (mc_ret < 0) {
        mcrypt_perror(mc_ret);
        return;
    }

    plaintext = gen_rand_data(data_size);
    if (plaintext == NULL) {
        return;
    }

    is_block = mcrypt_enc_is_block_mode(td);
    if (is_block) {
        block_size = mcrypt_enc_get_block_size(td);
        block_overlap = data_size % block_size;
        block_fill = block_size - block_overlap;
        if (padding == PADDING_NONE) {
            /* do nothing */
        }
        else if (padding == PADDING_PKCS7) {
            if (block_fill == 0) {
                /* ALWAYS add padding */
                block_fill = block_size;
            }
            plaintext = (unsigned char *)realloc(plaintext,
                                                 data_size + block_fill);
            for (i = 0; i < block_fill; i++) {
                plaintext[data_size+i] = block_fill;
            }
            data_size = data_size + block_fill;
            if ((data_size % block_size) != 0) {
                fprintf(stderr, "bad data size!\n");
                exit(1);
            }
        }
        else if (padding == PADDING_ZEROS) {
            if (block_overlap != 0) {
                plaintext = (unsigned char *)realloc(plaintext,
                                                     data_size + block_fill);
                for (i = 0; i < block_fill; i++) {
                    plaintext[data_size+i] = '\0';
                }
                data_size = data_size + block_fill;
            }
        }
        else {
            fprintf(stderr, "bad error\n");
            exit(1);
        }
    }

    ciphertext = malloc(data_size);
    if (ciphertext == NULL) {
        fprintf(stderr, "Out of memory\n");
        return;
    }

    memcpy( (void *)ciphertext, (void *)plaintext, data_size);

    mc_ret = mcrypt_generic(td, ciphertext, data_size);
    if (mc_ret == 0) {
        char *enc_key, *enc_iv, *enc_pt, *enc_ct;
        enc_key = dump_value( (void *)key, key_size );
        enc_iv  = dump_value( (void *)iv, iv_size );
        enc_pt  = dump_value( (void *)plaintext, data_size );
        enc_ct  = dump_value( (void *)ciphertext, data_size );

        printf("algo=%s,mode=%s,key=%s,iv=%s,padding=%s,pt=%s,ct=%s\n",
               testing_algo, testing_mode, enc_key, enc_iv,
               padding_name(padding), enc_pt, enc_ct);

        free(enc_key);
        free(enc_iv);
        free(enc_pt);
        free(enc_ct);
    }

    free(plaintext);
    free(ciphertext);

    mc_ret = mcrypt_generic_deinit(td);
    if (mc_ret < 0) {
        fprintf(stderr, "Error %d during deinit of %s in %s mode"
                " (%d-byte key)\n", testing_algo, testing_mode, key_size);
        return;
    }
}

/*
 * padding_name(padding)
 *
 * Returns the string name for the padding type.
 *
 */

const char *padding_name(padding_t padding) {
    switch(padding) {
        case PADDING_NONE:  return "none";
        case PADDING_PKCS7: return "pkcs7";
        case PADDING_ZEROS: return "zeros";
        default:            fprintf(stderr, "Invalid padding type\n");
                            exit(1);
    }
}


/*
 * list_key_sizes(td)
 *
 * Returns a pointer to an array of integer key sizes for the mcrypt
 * handle.  This returns the actual list, as opposed to
 * mcrypt_enc_get_supported_key_sizes which sometimes just returns a
 * formula to create the list.
 *
 * The list is terminated with a zero.
 *
 */
int *list_key_sizes(MCRYPT td) {
    int *list;
    int *key_sizes, n_key_sizes, max_size, i;

    key_sizes = mcrypt_enc_get_supported_key_sizes(td, &n_key_sizes);

    if (n_key_sizes == 0) {
        max_size = mcrypt_enc_get_key_size(td);
        list = malloc( (max_size + 1) * sizeof(int) );
        if (!list) {
            fprintf(stderr, "Out of memory\n");
            return NULL;
        }

        for (i = 0; i < max_size; i++) {
            list[i] = i;
        }
        list[max_size] = 0;
    }
    else {
        list = malloc( (n_key_sizes + 1) * sizeof(int) );
        if (!list) {
            fprintf(stderr, "Out of memory\n");
            return NULL;
        }

        for (i = 0; i < n_key_sizes; i++) {
            list[i] = key_sizes[i];
        }
        list[n_key_sizes] = 0;
        
        free(key_sizes);
    }

    return list;
}


/*
 * gen_rand_data(len)
 *
 * Returns a random key of byte length len. You need to free it when
 * you're done with it.
 *
 * This isn't truly random but it doesn't have to be as it's just
 * generating test cases.
 *
 */
unsigned char *gen_rand_data(unsigned int len) {
    unsigned char *key, *p;
    unsigned int i;

    p = key = malloc(len);
    if (key == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        *p++ = (unsigned char)(255L * drand48());
    }

    return key;
}


/*
 * dump_value(void *buffer, int len)
 *
 * Returns a string containing the buffer's contents encoded as
 * two-character hexadecimal bytes separated by spaces.
 *
 * Free it when you're done.
 *
 */

char *dump_value(void *buffer, int len) {
    char *enc, *p;
    unsigned char *buf;
    int i;

    buf = (unsigned char *)buffer;

    p = enc = malloc(len * 3);
    if (enc == NULL) {
        return NULL;
    }

    *p = '\0';

    for(i = 0; i < len; i++) {
        if (i != 0) {
            (*p++) = ' ';
        }
        sprintf(p, "%02x", buf[i]);
        p += 2;
    }
    (*++p) = '\0';

    return enc;
}

void dump_list(char **list, int len) {
    int i;
    for(i = 0; i < len; i++) {
        printf("%s\n", list[i]);
    }
}
