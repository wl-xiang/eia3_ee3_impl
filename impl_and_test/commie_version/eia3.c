#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "zuc.h"

/**
 * @brief get i_th word
 */
u32 GET_WORD(u32 *DATA, u32 i) {
	u32 WORD, ti;

	ti = i % 32;
	if (ti == 0) {
		WORD = DATA[i / 32];
	} else {
		WORD = (DATA[i / 32] << ti) | (DATA[i / 32 + 1] >> (32 - ti));
	}
	return WORD;
}

/**
 * @brief get i_th bit. resolution: u32 
 */
u8 GET_BIT_U32(u32 *DATA, u32 i) 
{ 
    return (DATA[i / 32] & (1 << (31 - (i % 32)))) ? 1 : 0; 
}

/** 
 * @brief get i_th bit. resolution: u8. 
 * @note the real resolution of message in NAS PDU is u8. 
 */
u8 GET_BIT_U8(u8 * DATA, u32 i)
{
	return (DATA[i / 8] & (1 << (7 - (i % 8)))) ? 1 : 0;
}

/**
 * @brief Check interity of message or ciphertext by computing MAC base on ZUC
 * @date 2024-06-15
 * 
 * @param IK Integrity Key, hex input
 * @param COUNT The counter, hex input
 * @param DIRECTION The direction of transmission, hex input
 * @param BEARER The bearer identity, hex input
 * @param LENGTH The bits of the input message
 * @param M input message, hex input
 * 
 * @return u8 MAC in network order
 */
u8* eia3_generates_mac(u8 *integrity_key, u32 count, u32 bearer, u32 direction, 
                        u8 *message, u32 length)
{
    static u32 mac = 0; // static memory for the result
    u32 *z, N, L, T, i;
    u8 IV[16];

    IV[0] = (count >> 24) & 0xFF;
    IV[1] = (count >> 16) & 0xFF;
    IV[2] = (count >> 8) & 0xFF;
    IV[3] = count & 0xFF;

    IV[4] = (bearer << 3) & 0xF8;
    IV[5] = IV[6] = IV[7] = 0;

    IV[8] = ((count >> 24) & 0xFF) ^ ((direction & 1) << 7);
    IV[9] = (count >> 16) & 0xFF;
    IV[10] = (count >> 8) & 0xFF;
    IV[11] = count & 0xFF;

    IV[12] = IV[4];
    IV[13] = IV[5];
    IV[14] = IV[6] ^ ((direction & 1) << 7);
    IV[15] = IV[7];

    N = length + 64;
    L = (N + 31) / 32;
    z = (u32 *)malloc(L * sizeof(u32));
    zuc(integrity_key, IV, z, L);

    T = 0;
    for (i = 0; i < length; i++) {
        if (GET_BIT_U8(message, i)) { // U8 in use
            T ^= GET_WORD(z, i);
        }
    }
    T ^= GET_WORD(z, length);

    mac = T ^ z[L - 1];
    free(z);

    mac = htonl(mac);   // trans to netSeq before return
    return (u8 *) &mac;
}