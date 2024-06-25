#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zuc.h"

/**
 * @brief Evolved Encryption Algorithm 3. Encrypt or Decrypt the message
 * @date 2024-06-15
 * 
 * @param cipher_key Confidentiality key, hex input
 * @param count The counter, hex input
 * @param bearer The bearer identity, hex input
 * @param direction The direction of transmission, hex input
 * @param message The input bit stream -> Message, hex input
 * @param length The bitwise length of the input message
 * @param out The output bit stream -> CypherText
 * 
 * @return ulRet
 */
int eea3_xcrypt(u8 *cipher_key, u32 count, u32 bearer, u32 direction, 
                u8 *message, u32 len_bit, 
                u8 *out)
{
    u8 IV[16];	// Initial vector
    u32 L = (len_bit + 31) / 32;		// len of u32
    u32 *z = (u32 *)malloc(L * sizeof(u32)); 	// L * 4 byte

    /* Initialization */
    IV[0] = (count >> 24) & 0xFF;
    IV[1] = (count >> 16) & 0xFF;
    IV[2] = (count >> 8) & 0xFF;
    IV[3] = count & 0xFF;

    IV[4] = ((bearer << 3) | ((direction & 1) << 2)) & 0xFC;
    IV[5] = 0;
    IV[6] = 0;
    IV[7] = 0;

    IV[8]  = IV[0];
    IV[9]  = IV[1];
    IV[10] = IV[2];
    IV[11] = IV[3];
    IV[12] = IV[4];
    IV[13] = IV[5];
    IV[14] = IV[6];
    IV[15] = IV[7];

    /* Keystream Generation */
    zuc(cipher_key, IV, z, L);  
    // FIXBUG: u32 array z need htonl()? yes
    for (int i = 0; i < L; i++) {
        z[i] = htonl(z[i]);
    }

    /* Encryption/Decryption */

    // FIXBUG: ref snow3g impl -> split u32 z[i] to 4 bytes
    // for (int i = 0; i < L; i++) { // u32
    //     message[i] ^= z[i];
    // }
    for (int i = 0; i < L * 4; i++) { // u8
        message[i] ^= *(((u8 *)z) + i);
    }

    /**
     * @note no need to mend here, because the length of input 
     *       message is full-byte long.
     */
    // mending the last byte's valid bits
    // FIXBUG: need modify here? u8?
    // int base = 32;
    // if (len_bit % base != 0) 
    // {
    //     int j = (len_bit / base);		// num of full 32-bit byte
    //     j = len_bit - j * base;		// num of valid byte in the last unfilled byte
    //     j = base - j;					// calculate right shift step
        
    //     // out_u32[L - 1] = out_u32[L - 1] >> j; // right shift
    //     // out_u32[L - 1] = out_u32[L - 1] << j; // recover
    //     printf("j : %d, len_bit : %d\n", j, len_bit);
    //     printf("last: %02x %02x %02x %02x\n", message[4 * L - 4], message[4 * L - 3], message[4 * L - 2], message[4 * L - 1]);
    //     message[4 * L - 1] >>= j;
    //     message[4 * L - 1] <<= j;
    // }

    free(z); // already got ciphertext, Keystream is out of use
    memcpy(out, message, L * 4);

    return 0;	// ulRet

}