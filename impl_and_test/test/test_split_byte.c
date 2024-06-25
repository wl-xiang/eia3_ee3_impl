#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint32_t u32;

void convert_u32_to_u8(u32 *input, u8 *output, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        output[i * 4]     = (u8) (input[i] >> 24);
        output[i * 4 + 1] = (u8) (input[i] >> 16);
        output[i * 4 + 2] = (u8) (input[i] >> 8);
        output[i * 4 + 3] = (u8) (input[i]);
    }
}

// 假设这是encryptMsgByEEA3函数的定义
void encryptMsgByEEA3(u8 *cipher_key, u32 count, u32 bearer, u32 direction, u32 length, u8 *message, u8 *out);

int main() {
    u8 CK1[16] = {0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29};
    u32 COUNT1 = 0x66035492;
    u32 BEARER1 = 0xf;
    u32 DIRECTION1 = 0;
    u32 LENGTH1 = 193;
    u32 M1[7] = {
        0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0x0bd675d9, 0x005875b2, 0x00000000
    };
    u32 expected_C1[7] = {
        0xa6c85fc6, 0x6afb8533, 0xaafc2518, 0xdfe78494, 0x0ee1e4b0, 0x30238cc8, 0x00000000
    };

    size_t num_u32bytes = (LENGTH1 + 31) / 32;

    // 分配u8数组
    u8 M1_u8[num_u32bytes * 4];
    u8 expected_C1_u8[num_u32bytes * 4];

    // 转换u32到u8
    convert_u32_to_u8(M1, M1_u8, num_u32bytes);
    convert_u32_to_u8(expected_C1, expected_C1_u8, num_u32bytes);

    // 分配输出数组
    u8 out_u8[num_u32bytes * 4];

    // 调用encryptMsgByEEA3函数
    encryptMsgByEEA3(CK1, COUNT1, BEARER1, DIRECTION1, LENGTH1, M1_u8, out_u8);

    // 输出结果
    for (size_t i = 0; i < num_u32bytes * 4; ++i) {
        printf("%02x ", out_u8[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    for (size_t i = 0; i < num_u32bytes * 4; ++i) {
        printf("%02x ", expected_C1_u8[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    return 0;
}

void encryptMsgByEEA3(u8 *cipher_key, u32 count, u32 bearer, u32 direction, u32 length, u8 *message, u8 *out) {
    // 示例实现：仅复制输入到输出
    for (u32 i = 0; i < length / 8; i++) {
        out[i] = message[i];
    }
}
