#ifndef _ZUC_H_
#define _ZUC_H_

typedef unsigned char u8; 
typedef unsigned int u32; 

/**
 * @brief Generate a {len}-byte KeyStream. The output ks is usually marked as z
 * @date 2024-06-15
 * 
 * @param[in] k Cipher Key(CK): generated from HSS(KASME, one of authentication vector field containing CK & IK)
 * @param[in] iv Initialization Vector
 * @param[out] ks Key Stream: output param, used for encryption or integrity checking
 * @param[in] len length of KeyStream, {len} bytes
 * 
 */
void zuc(u8* k, u8* iv, u32* ks, int len);

#endif