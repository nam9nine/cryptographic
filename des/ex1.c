#include <stdio.h>

typedef unsigned char BYTE;
typedef unsigned int UINT;

void IP(BYTE *in, BYTE *out);
void BtoW(BYTE *in, UINT *l, UINT *r);
void EP(UINT *r, BYTE *out);

BYTE ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};

BYTE E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

int main()
{
    BYTE plainText[8] = "abcdefgh";
    BYTE permutedText[8] = {0};

    IP(plainText, permutedText);

    printf("평문 : ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X ", plainText[i]);
    }
    printf("\n초기 전치 후 평문 : ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X ", permutedText[i]);
    }
    printf("\n");

    return 0;
}

void IP(BYTE *in, BYTE *out)
{
    int i;
    BYTE whereByte, whereBit, mask = 0x80;
    for (i = 0; i < 64; i++)
    {
        whereByte = (ip[i] - 1) / 8;
        whereBit = (ip[i] - 1) % 8;

        if (in[whereByte] & (mask >> whereBit))
            out[i / 8] |= mask >> (i % 8);
    }
}

void BtoW(BYTE *in, UINT *l, UINT *r)
{
    int i;

    for (i = 0; i < 8; i++)
    {
        if (i < 4)
        {
            *l |= (UINT)in[i] << (24 - (i * 8));
        }
        else
        {
            *r |= (UINT)in[i] << (56 - (i * 8));
        }
    }
}

void EP(UINT *r, BYTE *out)
{
    int i;
    UINT mask = 0x80000000;

    for (i = 0; i < 48; i++)
    {
        if (*r & (mask >> (E[i] - 1)))
        {
            out[i / 8] |= (BYTE)(0x80 >> (i % 8));
        }
    }
}
