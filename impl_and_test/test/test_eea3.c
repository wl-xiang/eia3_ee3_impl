#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zuc.h"
#include "inc.h"

int _mydebug_ = 0;

int test_raw = 0;
int test_u32_msg = 0;
int test_u8_msg = 0;

int is_test_sample1 = 1;
int is_test_sample2 = 1;
int is_test_sample3 = 1;
int is_test_sample4 = 1;
int is_test_sample5 = 1;

// void convert_u32_to_u8(u32 *input, u8 *output, size_t length) {
//     for (size_t i = 0; i < length; ++i) {
//         output[i * 4]     = (u8) (input[i] >> 24);
//         output[i * 4 + 1] = (u8) (input[i] >> 16);
//         output[i * 4 + 2] = (u8) (input[i] >> 8);
//         output[i * 4 + 3] = (u8) (input[i]);
//     }
// }

void print_hex(uint32_t *data, int length) {
    for (int i = 0; i < (length + 31) / 32; i++) {
        printf("%08x ", data[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    printf("\n");
}

void print_u8_arr(uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 4 == 0) printf(" ");
        if ((i + 1) % 32 == 0) printf("\n");
    }
    printf("\n");
}

int check_u8arr_is_same(uint8_t *arr1, uint8_t *arr2, int len) {
    int ok = 1;
    int pos[200] = {0};
    int num = 0;
    for (int i = 0; i < len; i++) {
        if (arr1[i] != arr2[i]) {
            ok = 0;
            pos[num++] = i;
        }
    }
    printf("  - Auto Check:  [%s]\n", (ok == 1 ? "same" : "diff"));
    if (!ok) {
        printf("  - Diff pos: ");
        for (int i = 0; i < num; i++) printf("%d ", pos[i]+1);
        printf("\n");
    }
}

void test_eea3(const char* sample_name, u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* expected_C) {
    // u32 *C = (u32 *)malloc(((LENGTH + 31) / 32) * sizeof(u32));
    // memset(C, 0, ((LENGTH + 31) / 32) * sizeof(u32));  // Clear the memory for C
    u8 C[2048] = {0};

    printf("\n--- %s ---\n", sample_name);
    if (_mydebug_) {
        printf("[input]:\n");
        printf("  - CK: ");
        for(int i = 0; i < 16; i++) {
            printf("%02x ", CK[i]);
        }
        printf("\n  - COUNT: \t%08x\n  - BEARER: \t%08x\n  - DIRECTION: \t%08x\n  - LENGTH: \t%08x\n", COUNT, BEARER, DIRECTION, LENGTH);
        printf("  - Plaintext: \t\n");
        print_hex(M, LENGTH);
    }

    // split u32* to 4x len u8*
    u32 num_u32bytes = (LENGTH + 31) / 32;
    // 分配u8数组
    // u8 M_u8[num_u32bytes * 4];
    // u8 expected_C_u8[num_u32bytes * 4];
    // // 转换u32到u8
    // convert_u32_to_u8(M, M_u8, num_u32bytes);
    // convert_u32_to_u8(expected_C, expected_C_u8, num_u32bytes);
    // 分配输出数组
    u8 out_u8[num_u32bytes * 4];


    EEA3_Encrypt_or_Decrypt(CK, COUNT, BEARER, DIRECTION, M, LENGTH, C);


    printf("[output]:\n");
    printf("  - Ciphertext: \t\n");
    print_hex((u32 *)C, LENGTH);
    printf("  - Expected:   \t\n");
    print_hex(expected_C, LENGTH);
    
    // Compare actual output with expected output
    // int match = 1;
    // for (int i = 0; i < (LENGTH + 31) / 32; i++) {
    //     if (C[i] != expected_C[i]) {
    //         match = 0;
    //         break;
    //     }
    // }
    // // for (int i = 0; i < (LENGTH + 7) / 8; i++) {
    // //     if (expected_C_u8[i] != out_u8[i]) {
    // //         match = 0;
    // //         break;
    // //     }
    // // }
    // if (match) {
    //     printf("--- %s Test Passed ---\n", sample_name);
    // } else {
    //     printf("--- %s Test Failed ---\n", sample_name);
    // }

    // free(C); // allocated at stack, no need for free
}

void test_eea3_u32_msg_input(const char* sample_name, u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* expected_C) {
    printf("\n--- %s ---\n", sample_name);

    u32 C[2048] = {0};

    eea3_test_u32_msg(CK, COUNT, BEARER, DIRECTION, M, LENGTH, C);

    printf("[output]:\n");
    printf("  - Ciphertext: \t\n");
    print_hex(C, LENGTH);

    printf("  - Expected:   \t\n");
    print_hex(expected_C, LENGTH);
}

void test_eea3_u8_msg_input(const char* sample_name, u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u8* M, u8* expected_C) {
    printf("\n--- %s ---\n", sample_name);

    u8 C[2048] = {0};
    
    eea3_test_u8_msg(CK, COUNT, BEARER, DIRECTION, M, LENGTH, C);

    int print_len = 4 * ((LENGTH + 31) / 32);
    printf("[output %d len]:\n", print_len);
    printf("  - Ciphertext: \t\n");
    print_u8_arr(M, print_len);

    printf("  - Expected:   \t\n");
    print_u8_arr(expected_C, print_len);

    check_u8arr_is_same(M, expected_C, print_len);
}

void trans_u32arr_to_u8arr(const uint32_t *src, uint8_t *dst, size_t src_len) {
    for (size_t i = 0; i < src_len; ++i) {
        // 将每个u32元素拆分为4个u8元素
        dst[i * 4 + 0] = (src[i] >> 24) & 0xff; // 取高8位
        dst[i * 4 + 1] = (src[i] >> 16) & 0xff; // 取次高8位
        dst[i * 4 + 2] = (src[i] >> 8)  & 0xff;  // 取次低8位
        dst[i * 4 + 3] = src[i]        & 0xff;   // 取低8位
    }
}

int main() {
    // Sample 1
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

    u8 msg1_u8[7 * 4] = {0};    trans_u32arr_to_u8arr(M1, msg1_u8, 7);
    // for (int i = 0; i < 28; i++) printf("%02x ", msg1_u8[i]);
    u8 ansMsg1_u8[7 * 4] = {0}; trans_u32arr_to_u8arr(expected_C1, ansMsg1_u8, 7);

    
    // Sample 2
    u8 CK2[16] = {0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
    u32 COUNT2 = 0x56823;
    u32 BEARER2 = 0x18;
    u32 DIRECTION2 = 0x1;
    u32 LENGTH2 = 800;
    u32 M2[25] = {
        0x14a8ef69, 0x3d678507, 0xbbe7270a, 0x7f67ff50, 0x06c3525b, 0x9807e467, 0xc4e56000, 0xba338f5d,
        0x42955903, 0x67518222, 0x46c80d3b, 0x38f07f4b, 0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38,
        0x2bf1ee97, 0x2fbf9977, 0xbada8945, 0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f,
        0x01ba220d
    };
    u32 expected_C2[25] = {
        0x131d43e0, 0xdea1be5c, 0x5a1bfd97, 0x1d852cbf, 0x712d7b4f, 0x57961fea, 0x3208afa8, 0xbca433f4,
        0x56ad09c7, 0x417e58bc, 0x69cf8866, 0xd1353f74, 0x865e8078, 0x1d202dfb, 0x3ecff7fc, 0xbc3b190f,
        0xe82a204e, 0xd0e350fc, 0x0f6f2613, 0xb2f2bca6, 0xdf5a473a, 0x57a4a00d, 0x985ebad8, 0x80d6f238,
        0x64a07b01
    };
    u8 msg2_u8[25 * 4] = {0};   trans_u32arr_to_u8arr(M2, msg2_u8, 25);
    u8 ansMsg2_u8[25 * 4] = {0};trans_u32arr_to_u8arr(expected_C2, ansMsg2_u8, 25);


    // Sample 3
    u8 CK3[16] = {0xd4, 0x55, 0x2a, 0x8f, 0xd6, 0xe6, 0x1c, 0xc8, 0x1a, 0x20, 0x09, 0x14, 0x1a, 0x29, 0xc1, 0x0b};
    u32 COUNT3 = 0x76452ec1;
    u32 BEARER3 = 0x2;
    u32 DIRECTION3 = 0x1;
    u32 LENGTH3 = 1570;
    u32 M3[50] = {
        0x38f07f4b, 0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38, 0x2bf1ee97, 0x2fbf9977, 0xbada8945,
        0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f, 0x01ba220d, 0x3ca4ec41, 0xe074595f,
        0x54ae2b45, 0x4fd97143, 0x20436019, 0x65cca85c, 0x2417ed6c, 0xbec3bada, 0x84fc8a57, 0x9aea7837,
        0xb0271177, 0x242a64dc, 0x0a9de71a, 0x8edee86c, 0xa3d47d03, 0x3d6bf539, 0x804eca86, 0xc584a905,
        0x2de46ad3, 0xfced6554, 0x3bd90207, 0x372b27af, 0xb79234f5, 0xff43ea87, 0x0820e2c2, 0xb78a8aae,
        0x61cce52a, 0x0515e348, 0xd196664a, 0x3456b182, 0xa07c406e, 0x4a207912, 0x71cfeda1, 0x65d535ec,
        0x5ea2d4df, 0x40000000
    };
    u32 expected_C3[50] = {
        0x8383b022, 0x9fcc0b9d, 0x2295ec41, 0xc977e9c2, 0xbb72e220, 0x378141f9, 0xc8318f3a, 0x270dfbcd,
        0xee6411c2, 0xb3044f17, 0x6dc6e00f, 0x8960f97a, 0xfacd131a, 0xd6a3b49b, 0x16b7babc, 0xf2a509eb,
        0xb16a75dc, 0xab14ff27, 0x5dbeeea1, 0xa2b155f9, 0xd52c2645, 0x2d0187c3, 0x10a4ee55, 0xbeaa78ab,
        0x4024615b, 0xa9f5d5ad, 0xc7728f73, 0x560671f0, 0x13e5e550, 0x085d3291, 0xdf7d5fec, 0xedded559,
        0x641b6c2f, 0x585233bc, 0x71e9602b, 0xd2305855, 0xbbd25ffa, 0x7f17ecbc, 0x042daae3, 0x8c1f57ad,
        0x8e8ebd37, 0x346f71be, 0xfdbb7432, 0xe0e0bb2c, 0xfc09bcd9, 0x6570cb0c, 0x0c39df5e, 0x29294e82,
        0x703a637f, 0x80000000
    };
    u8 msg3_u8[50 * 4] = {0};   trans_u32arr_to_u8arr(M3, msg3_u8, 50);
    u8 ansMsg3_u8[50 * 4] ={0}; trans_u32arr_to_u8arr(expected_C3, ansMsg3_u8, 50);
    

    // Sample 4
    u8 CK4[16] = {0xdb, 0x84, 0xb4, 0xfb, 0xcc, 0xda, 0x56, 0x3b, 0x66, 0x22, 0x7b, 0xfe, 0x45, 0x6f, 0x0f, 0x77};
    u32 COUNT4 = 0xe4850fe1;
    u32 BEARER4 = 0x10;
    u32 DIRECTION4 = 0x1;
    u32 LENGTH4 = 2798;
    u32 M4[88] = {
        0xe539f3b8, 0x973240da, 0x03f2b8aa, 0x05ee0a00, 0xdbafc0e1, 0x82055dfe, 0x3d7383d9, 0x2cef40e9,
        0x2928605d, 0x52d05f4f, 0x9018a1f1, 0x89ae3997, 0xce19155f, 0xb1221db8, 0xbb0951a8, 0x53ad852c,
        0xe16cff07, 0x382c93a1, 0x57de00dd, 0xb125c753, 0x9fd85045, 0xe4ee07e0, 0xc43f9e9d, 0x6f414fc4,
        0xd1c62917, 0x813f74c0, 0x0fc83f3e, 0x2ed7c45b, 0xa5835264, 0xb43e0b20, 0xafda6b30, 0x53bfb642,
        0x3b7fce25, 0x479ff5f1, 0x39dd9b5b, 0x995558e2, 0xa56be18d, 0xd581cd01, 0x7c735e6f, 0x0d0d97c4,
        0xddc1d1da, 0x70c6db4a, 0x12cc9277, 0x8e2fbbd6, 0xf3ba52af, 0x91c9c6b6, 0x4e8da4f7, 0xa2c266d0,
        0x2d001753, 0xdf089603, 0x93c5d568, 0x88bf49eb, 0x5c16d9a8, 0x0427a416, 0xbcb597df, 0x5bfe6f13,
        0x890a07ee, 0x1340e647, 0x6b0d9aa8, 0xf822ab0f, 0xd1ab0d20, 0x4f40b7ce, 0x6f2e136e, 0xb67485e5,
        0x07804d50, 0x4588ad37, 0xffd81656, 0x8b2dc403, 0x11dfb654, 0xcdead47e, 0x2385c343, 0x6203dd83,
        0x6f9c64d9, 0x7462ad5d, 0xfa63b5cf, 0xe08acb95, 0x32866f5c, 0xa787566f, 0xca93e6b1, 0x693ee15c,
        0xf6f7a2d6, 0x89d97417, 0x98dc1c23, 0x8e1be650, 0x733b18fb, 0x34ff880e, 0x16bbd21b, 0x47ac0000
    };
    u32 expected_C4[88] = {
        0x4bbfa91b, 0xa25d47db, 0x9a9f190d, 0x962a19ab, 0x323926b3, 0x51fbd39e, 0x351e05da, 0x8b8925e3,
        0x0b1cce0d, 0x12211010, 0x95815cc7, 0xcb631950, 0x9ec0d679, 0x40491987, 0xe13f0aff, 0xac332aa6,
        0xaa64626d, 0x3e9a1917, 0x519e0b97, 0xb655c6a1, 0x65e44ca9, 0xfeac0790, 0xd2a321ad, 0x3d86b79c,
        0x5138739f, 0xa38d887e, 0xc7def449, 0xce8abdd3, 0xe7f8dc4c, 0xa9e7b733, 0x14ad310f, 0x9025e619,
        0x46b3a56d, 0xc649ec0d, 0xa0d63943, 0xdff592cf, 0x962a7efb, 0x2c8524e3, 0x5a2a6e78, 0x79d62604,
        0xef268695, 0xfa400302, 0x7e22e608, 0x30775220, 0x64bd4a5b, 0x906b5f53, 0x1274f235, 0xed506cff,
        0x0154c754, 0x928a0ce5, 0x476f2cb1, 0x020a1222, 0xd32c1455, 0xecaef1e3, 0x68fb344d, 0x1735bfbe,
        0xdeb71d0a, 0x33a2a54b, 0x1da5a294, 0xe679144d, 0xdf11eb1a, 0x3de8cf0c, 0xc0619179, 0x74f35c1d,
        0x9ca0ac81, 0x807f8fcc, 0xe6199a6c, 0x7712da86, 0x5021b04c, 0xe0439516, 0xf1a526cc, 0xda9fd9ab,
        0xbd53c3a6, 0x84f9ae1e, 0x7ee6b11d, 0xa138ea82, 0x6c5516b5, 0xaadf1abb, 0xe36fa7ff, 0xf92e3a11,
        0x76064e8d, 0x95f2e488, 0x2b5500b9, 0x3228b219, 0x4a475c1a, 0x27f63f9f, 0xfd264989, 0xa1bc0000
    };
    u8 msg4_u8[88 * 4] = {0};   trans_u32arr_to_u8arr(M4, msg4_u8, 88);
    u8 ansMsg4_u8[88 * 4] = {0};trans_u32arr_to_u8arr(expected_C4, ansMsg4_u8, 88);

    

    // Sample 5
    u8 CK5[16] = {0xe1, 0x3f, 0xed, 0x21, 0xb4, 0x6e, 0x4e, 0x7e, 0xc3, 0x12, 0x53, 0xb2, 0xbb, 0x17, 0xb3, 0xe0};
    u32 COUNT5 = 0x2738cdaa;
    u32 BEARER5 = 0x1a;
    u32 DIRECTION5 = 0x0;
    u32 LENGTH5 = 4019;
    u32 M5[126] = {
        0x8d74e20d, 0x54894e06, 0xd3cb13cb, 0x3933065e, 0x8674be62, 0xadb1c72b, 0x3a646965, 0xab63cb7b,
        0x7854dfdc, 0x27e84929, 0xf49c64b8, 0x72a490b1, 0x3f957b64, 0x827e71f4, 0x1fbd4269, 0xa42c97f8,
        0x24537027, 0xf86e9f4a, 0xd82d1df4, 0x51690fdd, 0x98b6d03f, 0x3a0ebe3a, 0x312d6b84, 0x0ba5a182,
        0x0b2a2c97, 0x09c090d2, 0x45ed267c, 0xf845ae41, 0xfa975d33, 0x33ac3009, 0xfd40eba9, 0xeb5b8857,
        0x14b768b6, 0x97138baf, 0x21380eca, 0x49f644d4, 0x8689e421, 0x5760b906, 0x739f0d2b, 0x3f091133,
        0xca15d981, 0xcbe401ba, 0xf72d05ac, 0xe05cccb2, 0xd297f4ef, 0x6a5f58d9, 0x1246cfa7, 0x7215b892,
        0xab441d52, 0x78452795, 0xccb7f5d7, 0x9057a1c4, 0xf77f80d4, 0x6db2033c, 0xb79bedf8, 0xe60551ce,
        0x10c667f6, 0x2a97abaf, 0xabbcd677, 0x2018df96, 0xa282ea73, 0x7ce2cb33, 0x1211f60d, 0x5354ce78,
        0xf9918d9c, 0x206ca042, 0xc9b62387, 0xdd709604, 0xa50af16d, 0x8d35a890, 0x6be484cf, 0x2e74a928,
        0x99403643, 0x53249b27, 0xb4c9ae29, 0xeddfc7da, 0x6418791a, 0x4e7baa06, 0x60fa6451, 0x1f2d685c,
        0xc3a5ff70, 0xe0d2b742, 0x92e3b8a0, 0xcd6b04b1, 0xc790b8ea, 0xd2703708, 0x540dea2f, 0xc09c3da7,
        0x70f65449, 0xe84d817a, 0x4f551055, 0xe19ab850, 0x18a0028b, 0x71a144d9, 0x6791e9a3, 0x57793350,
        0x4eee0060, 0x340c69d2, 0x74e1bf9d, 0x805dcbcc, 0x1a6faa97, 0x6800b6ff, 0x2b671dc4, 0x63652fa8,
        0xa33ee509, 0x74c1c21b, 0xe01eabb2, 0x16743026, 0x9d72ee51, 0x1c9dde30, 0x797c9a25, 0xd86ce74f,
        0x5b961be5, 0xfdfb6807, 0x814039e7, 0x137636bd, 0x1d7fa9e0, 0x9efd2007, 0x505906a5, 0xac45dfde,
        0xed7757bb, 0xee745749, 0xc2963335, 0x0bee0ea6, 0xf409df45, 0x80160000
    };
    u32 expected_C5[126] = {
        0x94eaa4aa, 0x30a57137, 0xddf09b97, 0xb25618a2, 0x0a13e2f1, 0x0fa5bf81, 0x61a879cc, 0x2ae797a6,
        0xb4cf2d9d, 0xf31debb9, 0x905ccfec, 0x97de605d, 0x21c61ab8, 0x531b7f3c, 0x9da5f039, 0x31f8a064,
        0x2de48211, 0xf5f52ffe, 0xa10f392a, 0x04766998, 0x5da454a2, 0x8f080961, 0xa6c2b62d, 0xaa17f33c,
        0xd60a4971, 0xf48d2d90, 0x9394a55f, 0x48117ace, 0x43d708e6, 0xb77d3dc4, 0x6d8bc017, 0xd4d1abb7,
        0x7b7428c0, 0x42b06f2f, 0x99d8d07c, 0x9879d996, 0x00127a31, 0x985f1099, 0xbbd7d6c1, 0x519ede8f,
        0x5eeb4a61, 0x0b349ac0, 0x1ea23506, 0x91756bd1, 0x05c974a5, 0x3eddb35d, 0x1d4100b0, 0x12e522ab,
        0x41f4c5f2, 0xfde76b59, 0xcb8b96d8, 0x85cfe408, 0x0d1328a0, 0xd636cc0e, 0xdc05800b, 0x76acca8f,
        0xef672084, 0xd1f52a8b, 0xbd8e0993, 0x320992c7, 0xffbae17c, 0x408441e0, 0xee883fc8, 0xa8b05e22,
        0xf5ff7f8d, 0x1b48c74c, 0x468c467a, 0x028f09fd, 0x7ce91109, 0xa570a2d5, 0xc4d5f4fa, 0x18c5dd3e,
        0x4562afe2, 0x4ef77190, 0x1f59af64, 0x5898acef, 0x088abae0, 0x7e92d52e, 0xb2de5504, 0x5bb1b7c4,
        0x164ef2d7, 0xa6cac15e, 0xeb926d7e, 0xa2f08b66, 0xe1f759f3, 0xaee44614, 0x725aa3c7, 0x482b3084,
        0x4c143ff8, 0x5b53f1e5, 0x83c50125, 0x7dddd096, 0xb81268da, 0xa303f172, 0x34c23335, 0x41f0bb8e,
        0x190648c5, 0x807c866d, 0x71932286, 0x09adb948, 0x686f7de2, 0x94a802cc, 0x38f7fe52, 0x08f5ea31,
        0x96d0167b, 0x9bdd02f0, 0xd2a5221c, 0xa508f893, 0xaf5c4b4b, 0xb9f4f520, 0xfd84289b, 0x3dbe7e61,
        0x497a7e2a, 0x584037ea, 0x637b6981, 0x127174af, 0x57b471df, 0x4b2768fd, 0x79c1540f, 0xb3edf2ea,
        0x22cb69be, 0xc0cf8d93, 0x3d9c6fdd, 0x645e8505, 0x91cca3d6, 0x2c0cc000
    };

    u8 msg5_u8[126 * 4] = {0};   trans_u32arr_to_u8arr(M5, msg5_u8, 126);
    u8 ansMsg5_u8[126 * 4] = {0};trans_u32arr_to_u8arr(expected_C5, ansMsg5_u8, 126);



    /****************************************************************
     * 
     */
    if (is_test_sample1) {
        if (test_raw) 
            test_eea3("Sample 1", CK1, COUNT1, BEARER1, DIRECTION1, LENGTH1, M1, expected_C1);
        if (test_u32_msg) 
            test_eea3_u32_msg_input("Sample 1", CK1, COUNT1, BEARER1, DIRECTION1, LENGTH1, M1, expected_C1);
        if (test_u8_msg) 
            test_eea3_u8_msg_input("Sample 1", CK1, COUNT1, BEARER1, DIRECTION1, LENGTH1-1, msg1_u8, ansMsg1_u8);

    }

    if (is_test_sample2) {
        if (test_raw) 
            test_eea3("Sample 2", CK2, COUNT2, BEARER2, DIRECTION2, LENGTH2, M2, expected_C2);
        if (test_u32_msg)
            test_eea3_u32_msg_input("Sample 2", CK2, COUNT2, BEARER2, DIRECTION2, LENGTH2, M2, expected_C2);
        if (test_u8_msg) 
            test_eea3_u8_msg_input("Sample 2", CK2, COUNT2, BEARER2, DIRECTION2, LENGTH2, msg2_u8, ansMsg2_u8);
    }
    
    if (is_test_sample3) {
        if (test_raw)
            test_eea3("Sample 3", CK3, COUNT3, BEARER3, DIRECTION3, LENGTH3, M3, expected_C3);
        if (test_u32_msg)
            test_eea3_u32_msg_input("Sample 3", CK3, COUNT3, BEARER3, DIRECTION3, LENGTH3, M3, expected_C3);
        if (test_u8_msg)
            test_eea3_u8_msg_input("Sample 3", CK3, COUNT3, BEARER3, DIRECTION3, LENGTH3, msg3_u8, ansMsg3_u8);
    }

    if (is_test_sample4) {
        if (test_raw)
            test_eea3("Sample 4", CK4, COUNT4, BEARER4, DIRECTION4, LENGTH4, M4, expected_C4);
        if (test_u32_msg)
            test_eea3_u32_msg_input("Sample 4", CK4, COUNT4, BEARER4, DIRECTION4, LENGTH4, M4, expected_C4);
        if (test_u8_msg)
            test_eea3_u8_msg_input("Sample 4", CK4, COUNT4, BEARER4, DIRECTION4, LENGTH4, msg4_u8, ansMsg4_u8);
    }

    if (is_test_sample5) {
        if (test_raw)
            test_eea3("Sample 5", CK5, COUNT5, BEARER5, DIRECTION5, LENGTH5, M5, expected_C5);
        if (test_u32_msg)
            test_eea3_u32_msg_input("Sample 5", CK5, COUNT5, BEARER5, DIRECTION5, LENGTH5, M5, expected_C5);
        if (test_u8_msg)
            test_eea3_u8_msg_input("Sample 5", CK5, COUNT5, BEARER5, DIRECTION5, LENGTH5, msg5_u8, ansMsg5_u8);
    }

    /*********** real world dataset ************/
    u8 CK_v1[] = {0xb1, 0xe2, 0x41, 0xca, 0xce, 0x65, 0xe1, 0xbc, 0x91, 0xd6, 0x0b, 0xe4, 0x15, 0x34, 0xa7, 0xe5};
    u8 M_v1[16] = {0x80, 0x86, 0x1d, 0x28, 0xee, 0xe9, 0xca, 0x3b, 0x66, 0xd6, 0x12, 0x00, 0x12};
    u32 COUNT_v1 = 0x0;
    u32 BEARER_v1 = 0x0;
    u32 DIRECTION_v1 = 0x0;
    u32 LENGTH_v1 = 13 << 3;
    u8 C_v1[16];
    u8 C_EXPECT_v1[16] = {0x07, 0x5e,0x23,0x09,0x83, 0x96, 0x57, 0x01,0x34, 0x91,0x63, 0x01, 0xf0};
    test_eea3_u8_msg_input("valid dataset 1", CK_v1, COUNT_v1, BEARER_v1, DIRECTION_v1, LENGTH_v1, M_v1, C_EXPECT_v1);


    u8 CK_v2[] = {0x17, 0x96, 0x60, 0xE9, 0xD2, 0x89, 0x45, 0x77, 0x5D, 0xF4, 0x79, 0x87, 0xBF, 0x2E, 0x77, 0x3A};

    u8 M_v2[80] = {0x7E, 0x00, 0x42, 0x01, 0x01, 0x77, 0x00, 0x0B, 0xF2, 0x64, 0xF6, 0x29, 0x01, 0x00, 0x83, 0x5C,
               0x00, 0x00, 0x01, 0x54, 0x07, 0x00, 0x64, 0xF6, 0x29, 0x00, 0x00, 0x51, 0x15, 0x04, 0x01, 0x01,
               0x01, 0x02, 0x31, 0x09, 0x01, 0x01, 0x01, 0x02, 0x04, 0x01, 0x11, 0x11, 0x11, 0x21, 0x02, 0x7D, 
               0x00, 0x50, 0x02, 0x00, 0x00, 0x27, 0x07, 0x80, 0x64, 0xF6, 0x29, 0x00, 0x00, 0x91, 0x5E, 0x01,
               0x12, 0x34, 0x08, 0x03, 0x04, 0x11, 0xF9, 0x03, 0x02, 0x21, 0xF0, 0xA0, 0x51, 0x01, 0x01, 0xFF};
     
    u32 COUNT_v2 = 0x1;
    u32 BEARER_v2 = 0x1;
    u32 DIRECTION_v2 = 0x1;
    u32 LENGTH_v2 = 79 << 3;
    u8 C_v2[80] = {0xFF};
    
    u8 C_EXPECT_v2[80] = {0x47, 0x2b, 0x21, 0xc4, 0x66, 0x5e, 0x7f, 0xe3, 0x52, 0xce, 0x2c, 0x72, 0xb5, 0x67, 0xc1, 0xd2,
                       0x49, 0x5f, 0xbd, 0xce, 0x22, 0x11, 0x94, 0x2d, 0xfa, 0xa7, 0xf4, 0x76, 0x4d, 0x1e, 0x29, 0x03,
                       0x20, 0x3d, 0x05, 0x37, 0x7f, 0x3c, 0x5a, 0x2e, 0x45, 0x93, 0x18, 0x08, 0xe3, 0xbf, 0x05, 0xf8,
                       0xef, 0x72, 0x61, 0x08, 0x12, 0xdc, 0x9a, 0xf2, 0xbd, 0x88, 0x84, 0xb2, 0x52, 0x32, 0x9b, 0x28,
                       0x33, 0xea, 0x45, 0x28, 0x93, 0x98, 0xe2, 0xc2, 0x4d, 0x58, 0x16, 0x7b, 0x5a, 0xa9, 0xe3, 0xFF};

    test_eea3_u8_msg_input("valid dataset 2", CK_v2, COUNT_v2, BEARER_v2, DIRECTION_v2, LENGTH_v2, M_v2, C_EXPECT_v2);

    return 0;
}
// gcc test_eea3.c ../src/eea3.c ../src/zuc.c -I ../src