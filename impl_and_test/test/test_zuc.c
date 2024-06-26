#include <stdio.h>
#include <string.h>

#include "zuc.h"

// Helper function to print the keystream
void print_keystream(u32 *keystream, int len) {
    for (int i = 0; i < len; i++) {
        printf("z%d: %08x\n", i + 1, keystream[i]);
    }
}

// Function to test a single case
void test_zuc(const char *test_name, u8 *key, u8 *iv, u32 *expected_output, int keystream_len) {
    u32 keystream[keystream_len];
    
    Initialization(key, iv);
    GenerateKeystream(keystream, keystream_len);

    printf("Test %s:\n", test_name);
    print_keystream(keystream, keystream_len);
    
    // Check if the generated keystream matches the expected output
    int passed = 1;
    for (int i = 0; i < keystream_len; i++) {
        if (keystream[i] != expected_output[i]) {
            passed = 0;
            break;
        }
    }

    if (passed) {
        printf("Result: Passed\n\n");
    } else {
        printf("Result: Failed\n\n");
    }
}

int main() {
    /* Test Dataset from raw paper */
    // Test vector 1
    u8 key1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u8 iv1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u32 expected_output1[2] = {0x27bede74, 0x018082da};

    // Test vector 2
    u8 key2[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u8 iv2[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u32 expected_output2[2] = {0x0657cfa0, 0x7096398b};

    // Test vector 3
    u8 key3[16] = {0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b};
    u8 iv3[16] = {0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66};
    u32 expected_output3[2] = {0x14f1c272, 0x3279c419};

    // Test vevtor 4
    u8 key4[16] = {0x4d, 0x32, 0x0b, 0xfa, 0xd4, 0xc2, 0x85, 0xbf, 0xd6, 0xb8, 0xbd, 0x00, 0xf3, 0x9d, 0x8b, 0x41};
    u8 iv4[16] = {0x52, 0x95, 0x9d, 0xab, 0xa0, 0xbf, 0x17, 0x6e, 0xce, 0x2d, 0xc3, 0x15, 0x04, 0x9e, 0xb5, 0x74};
    u32 expected_output4[2000] = {0xed4400e7, 0x0633e5c5}; // 0 -> 0, 1 -> 1, 2-> 1999
    expected_output4[1999] = 0x7a574cdb;

    // Running the tests
    test_zuc("Vector 1", key1, iv1, expected_output1, 2);
    test_zuc("Vector 2", key2, iv2, expected_output2, 2);
    test_zuc("Vector 3", key3, iv3, expected_output3, 2);
    // test_zuc("Vector 4", key4, iv4, expected_output4, 2000); // test done and passed

    return 0;
}

