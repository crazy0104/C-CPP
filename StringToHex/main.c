#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

char CharToHex(char ch)
{
    if(ch >= '0' && ch <= '9')
        return (ch - '0');
    else if(ch >= 'A' && ch <= 'F')
        return (ch - 'A' + 10);
    else if(ch >= 'a' && ch <= 'z')
        return (ch - 'a' + 10);
    else
        return 0;
}
void printHexPairs(const char *input) {
    size_t len = strlen(input);
    
    // 确保输入长度为偶数
    if (len % 2 != 0) {
        printf("Error: Input length must be even.\n");
        return;
    }

    // 遍历字符对
    for (size_t i = 0; i < len; i += 2) {

        uint8_t byte1 = CharToHex(input[i]);
        uint8_t byte2 = CharToHex(input[i + 1]);

        // 将两个字符转换为一个字节
        uint8_t hexValue = (byte1 << 4) | byte2;

        // 输出十六进制值，逗号隔开
        printf("0x%02X", hexValue);

        // 除了最后一对，加上逗号
        if (i + 2 < len) {
            printf(", ");
        }
    }

    printf("\n");
}

int main() {
    const char *input = "DE706532232DF0F2928CCDF1C40BDAF9";
    printHexPairs(input);
    system("pause");
    return 0;
}
