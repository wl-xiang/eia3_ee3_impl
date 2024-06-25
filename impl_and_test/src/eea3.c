#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zuc.h"

/**
 * @brief Evolved Encryption Algorithm 3
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
int EEA3_Encrypt_or_Decrypt(u8 *cipher_key, u32 count, u32 bearer, u32 direction, 
							u32 *message, u32 length, 
							u8 *out)
{
    u8 IV[16];	// Initial vector
    u32 L = (length + 31) / 32;		// Get int upper case
    u32 *z = (u32 *)malloc(L * sizeof(u32)); 	// ZUC output. Caution: It is a pointer!
	u32 *out_u32 = (u32 *)out; 	// Convert out to u32 pointer

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
    /// return the Keystream to z
    zuc(cipher_key, IV, z, L);  

    /* Encryption/Decryption */
    /// Encryption/decryption operations are the same operations 
    /// and are performed by the exclusive OR of the input message
    /// with the generated keystream z.
    int debug_ = 0;
    for (int i = 0; i < L; i++)
    {
        out_u32[i] = (message[i] ^ z[i]);
        if (debug_) printf("message[%d]: %08x, z[%d]: %08x, out_32[%d]: %08x\n", i, message[i], i, z[i], i, out_u32[i]);
    }

    // mending the last byte's valid bits
    if (length % 32 != 0) 
    {
        int j = (length / 32);		// num of full 32-bit byte
        j = length - j * 32;		// num of valid byte in the last unfilled byte
        j = 32 - j;					// calculate right shift step
        out_u32[L - 1] = out_u32[L - 1] >> j; // right shift
        out_u32[L - 1] = out_u32[L - 1] << j; // recover
    }

    free(z); // already got ciphertext, Keystream is out of use

    return 0;	// ulRet
}






int eea3_test_u32_msg(u8 *cipher_key, u32 count, u32 bearer, u32 direction, 
                     u32 *message, u32 len_bit, 
                     u32 *out)
{
    u8 IV[16];	// Initial vector
    u32 L = (len_bit + 31) / 32;		// Get int upper case
    u32 *z = (u32 *)malloc(L * sizeof(u32)); 	// ZUC output. Caution: It is a pointer!
	// u32 *out_u32 = (u32 *)out; 	// Convert out to u32 pointer

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
    /// return the Keystream to z
    zuc(cipher_key, IV, z, L);  

    /* Encryption/Decryption */
    // fixbug: ref snow3g impl -> split u32 z[i] to 4 bytes
    for (int i = 0; i < L; i++)  
    {
        // out_u32[i] = (message[i] ^ z[i]);
        message[i] ^= z[i];
    }

    // mending the last byte's valid bits
    if (len_bit % 32 != 0) 
    {
        int j = (len_bit / 32);		// num of full 32-bit byte
        j = len_bit - j * 32;		// num of valid byte in the last unfilled byte
        j = 32 - j;					// calculate right shift step
        // out_u32[L - 1] = out_u32[L - 1] >> j; // right shift
        // out_u32[L - 1] = out_u32[L - 1] << j; // recover
        message[L - 1] >>= j;
        message[L - 1] <<= j;
    }

    free(z); // already got ciphertext, Keystream is out of use
    memcpy(out, message, L * 4);

    return 0;	// ulRet
}


int eea3_test_u8_msg(u8 *cipher_key, u32 count, u32 bearer, u32 direction, 
                     u8 *message, u32 len_bit, 
                     u8 *out)
{
    u8 IV[16];	// Initial vector
    u32 L = (len_bit + 31) / 32;		// len of u32
    u32 *z = (u32 *)malloc(L * sizeof(u32)); 	// L * 4 byte
    // u32 zero_bit = len_bit & 0x7;
	// u32 *out_u32 = (u32 *)out; 	// Convert out to u32 pointer

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

    /// return the Keystream to z
    zuc(cipher_key, IV, z, L);  

    // mask the keyStream
    // if (zero_bit > 0) {
	//   z[L - 1] = z[L - 1] & (u32)(0xFFFFFFFF << (8 - zero_bit));
	// }

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

    // int ceil_index = 0;
    // if (zero_bit > 0) {
    //     ceil_index = (len_bit + 7) >> 3;
    //     printf("ceil idx: %d ==== %d\n", ceil_index, len_bit);
    //     message[ceil_index - 1] = message[ceil_index - 1] & (u8)(0xFF << (8 - zero_bit));
    // }

    free(z); // already got ciphertext, Keystream is out of use
    memcpy(out, message, L * 4);

    // if (zero_bit > 0) {
	//   out[ceil_index - 1] = message[ceil_index - 1];
	// }

    return 0;	// ulRet

}