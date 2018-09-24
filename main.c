/* Deadline:    25-9-2018
 * Course:      Modern Cryptography.
 * Group:       SQL Injection
 * Students:    Levi van der Griendt, Ismail Mahdaoui, Zi Long Zhu, Niels Zwemmer
 * Description: This exercise belongs to week 3. This is the decryption part
 *              for the ciphertext as provided by Coursera here:
 *
 * https://www.coursera.org/learn/cryptography/supplement/zaK8x/programming-assignment-3
 * NOTE: This week we were helped by Paul Lagerweij (of group Spectre).
 * He helped us on our way by sharing ideas and approaches, which we then implemented
 * ourselves in this program. This code remains our own implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "oracle.h"

int main(int argc, char *argv[]) {
    unsigned char ctext[48], *modded_ctext;
    int tmp, blocksize, block1, block2, block3, pad = 0, m, *cur_letter;
    FILE *fpIn;

    // Check for number of arguments.
    if (argc != 2) {
        fprintf(stderr, "Usage: sample <filename>\n");
        return EXIT_FAILURE;
    }

    // Read in the file.
    fpIn = fopen(argv[1], "r");

    for(int i= 0; i < 48; i++) {
        int ret = fscanf(fpIn, "%02x", &tmp);
        (void) ret;
        ctext[i] = tmp;
    }

    // Close the read-in if the file.
    fclose(fpIn);

    // Connect to the Oracle server.
    Oracle_Connect();

    // Blocksize and the increment of 16 for each additional block.
    blocksize = 16;
    block1 = blocksize;
    block2 = 2 * blocksize;
    block3 = 3 * blocksize;

    modded_ctext = calloc(sizeof(unsigned char), block3+1);
    memcpy(modded_ctext, ctext, block3);
    modded_ctext[block3] = '\0';

    // Find the padding by modifying the required block in the ciphertext.
    // This is done by modifying until a decryption error occurs
    // on the server-end. The modification needs to occur on the second block,
    // hence i < block2.
    for (int i = blocksize; i < block2; i++) {
        modded_ctext[i] = 0;

        // If error occurs, padding is found.
        if (Oracle_Send(modded_ctext, 3) == 0) {
            pad = block2 - i;
            break;
        }
    }

    // Start outputting found values.
    printf("Padding found: %d\n\n", pad);
    printf("Characters found: ");
    fflush(stdout);

    int plaintext[block2 - pad];
    cur_letter = plaintext + block2 - pad - 1;

    memcpy(modded_ctext, ctext, block3);
    modded_ctext[block3] = '\0';

    /* This forloop tries to find the plaintext of the last block.
     * We start here because we can first subtract the padding from the right
     * side of the last block. Then we bruteforce possible characters until
     * we find the character for which the server returns 1 or true.
     * The decryption then succeeded and the character found is the
     * required one. The padding is increased so we can subtract this
     * padding from the next (in this case 2nd) block.
     */
    for (int i = 1; i <= block1 - pad; i++) {
        // Increment of padding size.
        for (int j = block2 - pad - i + 1; j < block2; j++)
            modded_ctext[j] = modded_ctext[j] ^ (pad + i - 1) ^ (pad + i);

        for (int B = 0; B < 256; B++) {
            modded_ctext[block2 - pad - i] = B;

            // Correct character is found, now convert it to the plaintext
            // equivalent using bitwise operation.
            if (Oracle_Send(modded_ctext, 3) == 1) {
                m = B ^ (pad + i) ^ ctext[block2 - pad - i];
                putchar(m);
                fflush(stdout);
                *(cur_letter--) = m;
                break;
            }
        }
    }

    free(modded_ctext);
    modded_ctext = calloc(sizeof(unsigned char), block2+1);
    memcpy(modded_ctext, ctext, block2);
    modded_ctext[block2] = '\0';

    /* Now try the same for the second block by modifying the first block.
     * We create a new padding for this block, since it isn't the last block
     * itself and we don't get the padding automatically.
     * After the padding is determined, bruteforce the correct character
     * as we did before.
     */
    for (int i = 1; i <= block1; i++) {
        for (int B = 0; B < 256; B++) {
            modded_ctext[block1 - i] = B;

            // Correct character is found, now convert it to the plaintext
            // equivalent using bitwise operation.
            if (Oracle_Send(modded_ctext, 2) == 1) {
                m = B ^ i ^ ctext[block1 - i];
                putchar(m);
                fflush(stdout);
                *(cur_letter--) = m;
                break;
            }
        }

        // Increment of padding size.
        for (int j = block1 - i; j < block1; j++)
            modded_ctext[j] = modded_ctext[j] ^ i ^ (i + 1);
    }

    // Print the found plaintext characters.
    printf("\n\nPlaintext: ");
    for (int i = 0; i < block2 - pad; i++)
        putchar(plaintext[i]);
    printf("\n");

    free(modded_ctext);
    Oracle_Disconnect();
    return EXIT_SUCCESS;
}
