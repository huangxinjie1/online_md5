#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];   // 存储MD5算法的中间状态
    uint32_t count[2];   // 存储输入消息的位数
    unsigned char buffer[64];   // 输入消息的缓冲区
} MD5_CTX;

// 常量表T
static const uint32_t T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
// 填充
static const unsigned char PADDING[64] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


// 辅助宏定义
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

// 函数声明
void MD5_Init(MD5_CTX* context);
void MD5_Update(MD5_CTX* context, const unsigned char* input, uint32_t inputLen);
void MD5_Final(unsigned char digest[16], MD5_CTX* context);

// MD5核心算法中的四个基本函数
uint32_t F(uint32_t x, uint32_t y, uint32_t z);
uint32_t G(uint32_t x, uint32_t y, uint32_t z);
uint32_t H(uint32_t x, uint32_t y, uint32_t z);
uint32_t I(uint32_t x, uint32_t y, uint32_t z);

// 将一个32位整数转换为四个8位整数
void encode(unsigned char* output, const uint32_t* input, uint32_t len);

// 将四个8位整数转换为一个32位整数
void decode(uint32_t* output, const unsigned char* input, uint32_t len);

// MD5核心算法的处理步骤
void MD5_Transform(uint32_t state[4], const unsigned char block[64]);

// MD5初始化
void MD5_Init(MD5_CTX* context) {
    context->count[0] = 0;
    context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}

// MD5基本转换步骤
void MD5_Transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];

    decode(x, block, 64);

    // Round 1
    FF(a, b, c, d, x[0], 7, T[0]);
    FF(d, a, b, c, x[1], 12, T[1]);
    FF(c, d, a, b, x[2], 17, T[2]);
    FF(b, c, d, a, x[3], 22, T[3]);
    FF(a, b, c, d, x[4], 7, T[4]);
    FF(d, a, b, c, x[5], 12, T[5]);
    FF(c, d, a, b, x[6], 17, T[6]);
    FF(b, c, d, a, x[7], 22, T[7]);
    FF(a, b, c, d, x[8], 7, T[8]);
    FF(d, a, b, c, x[9], 12, T[9]);
    FF(c, d, a, b, x[10], 17, T[10]);
    FF(b, c, d, a, x[11], 22, T[11]);
    FF(a, b, c, d, x[12], 7, T[12]);
    FF(d, a, b, c, x[13], 12, T[13]);
    FF(c, d, a, b, x[14], 17, T[14]);
    FF(b, c, d, a, x[15], 22, T[15]);

    // Round 2
    GG(a, b, c, d, x[1], 5, T[16]);
    GG(d, a, b, c, x[6], 9, T[17]);
    GG(c, d, a, b, x[11], 14, T[18]);
    GG(b, c, d, a, x[0], 20, T[19]);
    GG(a, b, c, d, x[5], 5, T[20]);
    GG(d, a, b, c, x[10], 9, T[21]);
    GG(c, d, a, b, x[15], 14, T[22]);
    GG(b, c, d, a, x[4], 20, T[23]);
    GG(a, b, c, d, x[9], 5, T[24]);
    GG(d, a, b, c, x[14], 9, T[25]);
    GG(c, d, a, b, x[3], 14, T[26]);
    GG(b, c, d, a, x[8], 20, T[27]);
    GG(a, b, c, d, x[13], 5, T[28]);
    GG(d, a, b, c, x[2], 9, T[29]);
    GG(c, d, a, b, x[7], 14, T[30]);
    GG(b, c, d, a, x[12], 20, T[31]);

    // Round 3
    HH(a, b, c, d, x[5], 4, T[32]);
    HH(d, a, b, c, x[8], 11, T[33]);
    HH(c, d, a, b, x[11], 16, T[34]);
    HH(b, c, d, a, x[14], 23, T[35]);
    HH(a, b, c, d, x[1], 4, T[36]);
    HH(d, a, b, c, x[4], 11, T[37]);
    HH(c, d, a, b, x[7], 16, T[38]);
    HH(b, c, d, a, x[10], 23, T[39]);
    HH(a, b, c, d, x[13], 4, T[40]);
    HH(d, a, b, c, x[0], 11, T[41]);
    HH(c, d, a, b, x[3], 16, T[42]);
    HH(b, c, d, a, x[6], 23, T[43]);
    HH(a, b, c, d, x[9], 4, T[44]);
    HH(d, a, b, c, x[12], 11, T[45]);
    HH(c, d, a, b, x[15], 16, T[46]);
    HH(b, c, d, a, x[2], 23, T[47]);

    // Round 4
    II(a, b, c, d, x[0], 6, T[48]);
    II(d, a, b, c, x[7], 10, T[49]);
    II(c, d, a, b, x[14], 15, T[50]);
    II(b, c, d, a, x[5], 21, T[51]);
    II(a, b, c, d, x[12], 6, T[52]);
    II(d, a, b, c, x[3], 10, T[53]);
    II(c, d, a, b, x[10], 15, T[54]);
    II(b, c, d, a, x[1], 21, T[55]);
    II(a, b, c, d, x[8], 6, T[56]);
    II(d, a, b, c, x[15], 10, T[57]);
    II(c, d, a, b, x[6], 15, T[58]);
    II(b, c, d, a, x[13], 21, T[59]);
    II(a, b, c, d, x[4], 6, T[60]);
    II(d, a, b, c, x[11], 10, T[61]);
    II(c, d, a, b, x[2], 15, T[62]);
    II(b, c, d, a, x[9], 21, T[63]);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset((unsigned char*)x, 0, sizeof(x));
}

// 将输入消息分组，每组512位
void MD5_Update(MD5_CTX* context, const unsigned char* input, uint32_t inputLen) {
    uint32_t i, index, partLen;

    index = (uint32_t)((context->count[0] >> 3) & 0x3F);

    if ((context->count[0] += (inputLen << 3)) < (inputLen << 3))
        context->count[1]++;

    context->count[1] += (inputLen >> 29);

    partLen = 64 - index;

    if (inputLen >= partLen) {
        memcpy((unsigned char*)&context->buffer[index], (unsigned char*)input, partLen);
        MD5_Transform(context->state, context->buffer);

        for (i = partLen; i + 64 <= inputLen; i += 64)
            MD5_Transform(context->state, &input[i]);

        index = 0;
    } else {
        i = 0;
    }

    memcpy((unsigned char*)&context->buffer[index], (unsigned char*)&input[i], inputLen - i);
}

// 生成MD5结果
void MD5_Final(unsigned char digest[16], MD5_CTX* context) {
    unsigned char bits[8];
    uint32_t index, padLen;

    encode(bits, context->count, 8);

    index = (uint32_t)((context->count[0] >> 3) & 0x3F);
    padLen = (index < 56) ? (56 - index) : (120 - index);

    MD5_Update(context, PADDING, padLen);
    MD5_Update(context, bits, 8);

    encode(digest, context->state, 16);

    memset((unsigned char*)context, 0, sizeof(*context));
}

// 将一个32位整数转换为四个8位整数
void encode(unsigned char* output, const uint32_t* input, uint32_t len) {
    uint32_t i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xFF);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xFF);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xFF);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xFF);
    }
}

// 将四个8位整数转换为一个32位整数
void decode(uint32_t* output, const unsigned char* input, uint32_t len) {
    uint32_t i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
                    (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
    }
}

// MD5核心算法中的四个基本函数
uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | ((~x) & z);
}

uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
    return (x & z) | (y & (~z));
}

uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
    return y ^ (x | (~z));
}
