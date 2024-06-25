#include "zuc.h"


extern int EEA3_Encrypt_or_Decrypt(u8 *cipher_key, u32 count, u32 bearer, u32 direction, 
                                    u32 *message, u32 length, 
                                    u8 *out);

extern u8* EIA3_Calculates_MAC(u8 *integrity_key, u32 count, u32 bearer, u32 direction, 
                                u32 *message, u32 length);



extern int eea3_test_u32_msg(u8 *cipher_key, u32 count, u32 bearer, u32 direction, 
                     u32 *message, u32 len_bit, 
                     u32 *out);
extern int eea3_test_u8_msg(u8 *cipher_key, u32 count, u32 bearer, u32 direction, 
                     u8 *message, u32 len_bit, 
                     u8 *out);