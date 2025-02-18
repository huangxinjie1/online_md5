#ifndef MD5_H
#define MD5_H

#include <stdint.h>

typedef struct {
    uint32_t state[4];         // MD5 算法的状态变量
    uint32_t count[2];         // 用于存储输入的位数
    unsigned char buffer[64];  // 输入数据的缓冲区
} MD5_CTX;

void MD5_Init(MD5_CTX* context);
// 初始化 MD5 算法的上下文

void MD5_Update(MD5_CTX* context, const unsigned char* input, uint32_t inputLen);
// 更新 MD5 算法的上下文，输入数据是 input 字符串的前 inputLen 字节

void MD5_Final(unsigned char digest[16], MD5_CTX* context);
// 完成 MD5 算法的计算，将结果存储在 digest 数组中

#endif // MD5_H
