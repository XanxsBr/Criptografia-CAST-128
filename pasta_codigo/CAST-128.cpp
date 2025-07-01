#include <cstring>
#include <locale.h>
#include "stdafx.h"
#include "cast_s.h"

#define _CRT_SECURE_NO_WARNINGS

UINT32 S[9][256];

void InitSubstitutionBoxes(void)
{
    memcpy(S[1], CAST_S_table0, sizeof(CAST_S_table0));
    memcpy(S[2], CAST_S_table1, sizeof(CAST_S_table1));
    memcpy(S[3], CAST_S_table2, sizeof(CAST_S_table2));
    memcpy(S[4], CAST_S_table3, sizeof(CAST_S_table3));
    memcpy(S[5], CAST_S_table4, sizeof(CAST_S_table4));
    memcpy(S[6], CAST_S_table5, sizeof(CAST_S_table5));
    memcpy(S[7], CAST_S_table6, sizeof(CAST_S_table6));
    memcpy(S[8], CAST_S_table7, sizeof(CAST_S_table7));
}
UINT32 fourByte2uint32(BYTE byte0, BYTE byte1, BYTE byte2, BYTE byte3)
{

    UINT32 u32ret = byte0;
    u32ret <<= 8;
    u32ret |= byte1;
    u32ret <<= 8;
    u32ret |= byte2;
    u32ret <<= 8;
    u32ret |= byte3;
    return u32ret;
};
UINT32 byteArr2uint(const BYTE byte[16], int iByte)
{
    assert(iByte <= 12);
    return fourByte2uint32(byte[iByte], byte[iByte + 1], byte[iByte + 2], byte[iByte + 3]);
}
void uint2fourByte(UINT32 uint, OUT BYTE &byte1, OUT BYTE &byte2, OUT BYTE &byte3, OUT BYTE &byte4)
{
    byte1 = (uint & 0xff000000) >> 24;
    byte2 = (uint & 0x00ff0000) >> 16;
    byte3 = (uint & 0x0000ff00) >> 8;
    byte4 = uint & 0x000000ff;
}
void uint2fourByte(UINT32 uint, OUT BYTE byte[16], int iByte)
{
    assert(iByte <= 12);
    byte[iByte] = (uint & 0xff000000) >> 24;
    byte[iByte + 1] = (uint & 0x00ff0000) >> 16;
    byte[iByte + 2] = (uint & 0x0000ff00) >> 8;
    byte[iByte + 3] = uint & 0x000000ff;
}
void byte82uint32LR(BYTE byte[8], UINT32 &L, UINT32 &R)
{
    L = byteArr2uint(byte, 0);
    R = byteArr2uint(byte, 4);
}
void uint32LR2byte8(OUT BYTE byte[8], UINT32 L, UINT32 R)
{
    uint2fourByte(L, byte, 0);
    uint2fourByte(R, byte, 4);
}
void CaluZX(OUT BYTE zx[16],
            int izx,
            IN const BYTE xz[16],
            int ixz,
            int iS5,
            int iS6,
            int iS7,
            int iS8,
            int iS,
            int iSi)
{
    UINT32 xz4byte = byteArr2uint(xz, ixz);

    //printf("index %d-%d xz4byte = %x\n", ixz, ixz + 4, xz4byte);

    UINT32 zx4byte = xz4byte ^ S[5][iS5] ^ S[6][iS6] ^ S[7][iS7] ^ S[8][iS8] ^ S[iS][iSi];

    //printf("zx4byte(openssl-l) %x =  %x^%x^%x^%x^%x^%x\n", zx4byte, xz4byte, S[5][iS5], S[6][iS6], S[7][iS7], S[8][iS8],
    //   S[iS][iSi]);

    uint2fourByte(zx4byte, zx, izx);
}

UINT32 CaluK(IN const BYTE zx[16], int izxS5, int izxS6, int izxS7, int izxS8, int iS, int izxsSi)
{
    return S[5][zx[izxS5]] ^ S[6][zx[izxS6]] ^ S[7][zx[izxS7]] ^ S[8][zx[izxS8]] ^ S[iS][zx[izxsSi]];
}

void CaluK(IN const BYTE key[16], OUT UINT32 Km[16], OUT UINT32 Kr[16])
{
    BYTE z[16];
    BYTE x[16];
    UINT32 k[33];

    memcpy(x, key, 16);
    UINT32 *K = &k[0];

CALCU_K16:
    CaluZX(z, 0, x, 0, x[0xD], x[0xF], x[0xC], x[0xE], 7, x[0x8]);
    CaluZX(z, 4, x, 8, z[0], z[2], z[1], z[3], 8, x[0xA]);
    CaluZX(z, 8, x, 0xC, z[7], z[6], z[5], z[4], 5, x[9]);
    CaluZX(z, 0xC, x, 4, z[0xA], z[9], z[0xB], z[8], 6, x[0xB]);

    for (int i = 0; i < 16; ++i)
    {
        //printf("z %d %x\n", i, z[i]);
    }
    K[1] = CaluK(z, 8, 9, 7, 6, 5, 2);
    K[2] = CaluK(z, 0xA, 0xB, 5, 4, 6, 6);
    K[3] = CaluK(z, 0xC, 0xD, 3, 2, 7, 9);
    K[4] = CaluK(z, 0xE, 0xF, 1, 0, 8, 0xC);
    CaluZX(x, 0, z, 8, z[5], z[7], z[4], z[6], 7, z[0]);
    CaluZX(x, 4, z, 0, x[0], x[2], x[1], x[3], 8, z[2]);
    CaluZX(x, 8, z, 4, x[7], x[6], x[5], x[4], 5, z[1]);
    CaluZX(x, 0xC, z, 0xC, x[0xA], x[9], x[0xB], x[8], 6, z[3]);
    K[5] = CaluK(x, 3, 2, 0xC, 0xD, 5, 8);
    K[6] = CaluK(x, 1, 0, 0xE, 0xF, 6, 0xD);
    K[7] = CaluK(x, 7, 6, 8, 9, 7, 3);
    K[8] = CaluK(x, 5, 4, 0xA, 0xB, 8, 7);
    CaluZX(z, 0, x, 0, x[0xD], x[0xF], x[0xC], x[0xE], 7, x[8]);
    CaluZX(z, 4, x, 8, z[0], z[2], z[1], z[3], 8, x[0xA]);
    CaluZX(z, 8, x, 0xC, z[7], z[6], z[5], z[4], 5, x[9]);
    CaluZX(z, 0xC, x, 4, z[0xA], z[9], z[0xB], z[8], 6, x[0xB]);
    K[9] = CaluK(z, 3, 2, 0xC, 0xD, 5, 9);
    K[10] = CaluK(z, 1, 0, 0xE, 0xF, 6, 0xC);
    K[11] = CaluK(z, 7, 6, 8, 9, 7, 2);
    K[12] = CaluK(z, 5, 4, 0xA, 0xB, 8, 6);
    CaluZX(x, 0, z, 8, z[5], z[7], z[4], z[6], 7, z[0]);
    CaluZX(x, 4, z, 0, x[0], x[2], x[1], x[3], 8, z[2]);
    CaluZX(x, 8, z, 4, x[7], x[6], x[5], x[4], 5, z[1]);
    CaluZX(x, 0xC, z, 0xC, x[0xA], x[9], x[0xB], x[8], 6, z[3]);
    K[13] = CaluK(x, 8, 9, 7, 6, 5, 3);
    K[14] = CaluK(x, 0xA, 0xB, 5, 4, 6, 7);
    K[15] = CaluK(x, 0xC, 0xD, 3, 2, 7, 8);
    K[16] = CaluK(x, 0xE, 0xF, 1, 0, 8, 0xD);

    for (int i = 1; i <= 16; ++i)
    {
        //printf("K %lld : %x\n", K - k + i, K[i]);
    }

    if (K == k)
    {
        K += 16;
        goto CALCU_K16;
    }
    for (int i = 1; i <= 16; ++i)
    {
        Km[i] = k[i];
        Kr[i] = k[16 + i] & 0x1f;
    }

    for (int i = 1; i <= 16; ++i)
    {
        //printf("i %d  Kmi %x, Kri %x\n", i, Km[i], Kr[i]);
    }
}
UINT32 uint32cirShiftL(UINT32 uint32, int nLeftShift)
{
    return(uint32 >> (32 - nLeftShift)) | (uint32 << nLeftShift);
}
UINT32 uint32cirShiftR(UINT32 uint32, int nRightShift)
{
    return(uint32 << (32 - nRightShift)) | (uint32 >> nRightShift);
}
UINT32 f(int iRound, int D, UINT32 Kmi, UINT32 Kri)
{
    UINT32 I;
    UINT32 u32f;
    BYTE Ia, Ib, Ic, Id;

    switch (iRound % 3)
    {
    case 1:
        I = uint32cirShiftL(Kmi + D, Kri);
        uint2fourByte(I, Ia, Ib, Ic, Id);
        u32f = (S[1][Ia] ^ S[2][Ib]) - S[3][Ic] + S[4][Id];
        break;
    case 2:
        I = uint32cirShiftL(Kmi ^ D, Kri);
        uint2fourByte(I, Ia, Ib, Ic, Id);
        u32f = ((S[1][Ia] - S[2][Ib]) + S[3][Ic]) ^ S[4][Id];
        break;
    case 0:
        I = uint32cirShiftL(Kmi - D, Kri);
        uint2fourByte(I, Ia, Ib, Ic, Id);
        u32f = ((S[1][Ia] + S[2][Ib]) ^ S[3][Ic]) - S[4][Id];
        break;
    default:
        u32f = 0;
        break;
    }
    return u32f;
}
void hexStringToBytes(const char* hexString, BYTE* output, int outputSize)
{
    for (int i = 0; i < outputSize; i++)
    {
        sscanf(hexString + 2 * i, "%2hhx", &output[i]);
    }
}
int main()
{
    setlocale(LC_ALL, "portuguese");
    InitSubstitutionBoxes();

    //criptação

    //  BYTE plaintext[BLOCK_SIZE];
    //  BYTE key[KEY_SIZE];
    // char keyInput[KEY_SIZE * 2 + 1];

//   printf("Digite a palavra (até %d caracteres): ", BLOCK_SIZE);
    //  fgets((char*)plaintext, BLOCK_SIZE + 1, stdin);

    //  printf("Digite a chave em hexadecimal (16 dígitos): ");
    //  scanf("%s", keyInput);

    //  hexStringToBytes(keyInput, key, KEY_SIZE);

    //  printf("Plaintext em bytes: ");
//   for (int i = 0; i < BLOCK_SIZE; i++) {
    //     printf("%02X ", plaintext[i]);
    //  }
    // printf("\nChave em bytes: ");
    //  for (int i = 0; i < KEY_SIZE; i++) {
    //     printf("%02X ", key[i]);
    //  }
    //printf("\n");

    const int ROUND = 16;
    UINT32 L[ROUND + 1];
    UINT32 R[ROUND + 1];

    BYTE plaintext[9];
    printf("Digite uma palavra (com 8 caracter): ");
    scanf("%8[^\n]", plaintext);


    BYTE key[KEY_SIZE];
    char input[KEY_SIZE * 2 + 1];

    printf("Digite a chave (em hexadecimal, 32 caracteres): ");
    scanf("%32s", input);

    hexStringToBytes(input, key, KEY_SIZE);

    // printf("Chave convertida:\n");
    //  for (int i = 0; i < KEY_SIZE; i++) {
    //     printf("0x%02X ", key[i]);
    // }
    printf("\n");
    //BYTE key[16] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };

    UINT32 Km[16];
    UINT32 Kr[16];

    CaluK(key, Km, Kr);


    byte82uint32LR(plaintext, L[0], R[0]);
    for (int i = 1; i <= ROUND; ++i)
    {
        L[i] = R[i - 1];
        R[i] = L[i - 1] ^ f(i, R[i - 1], Km[i], Kr[i]);
    }

    BYTE ciphertext[8];

    uint32LR2byte8(ciphertext, R[16], L[16]);
    // system("cls");
    printf("Texto Cifrado: ");
    for (int i = 0; i < 8; ++i)
    {
        printf("%x ", ciphertext[i]);
    }

    printf("\n");

    //descriptação
    for (int i = ROUND - 1; i >= 0; --i)
    {
        R[i] = L[i + 1];
        L[i] = R[i + 1] ^ f(i + 1, R[i], Km[i + 1], Kr[i + 1]);
    }

    BYTE orgText[8];
    uint32LR2byte8(orgText, L[0], R[0]);

    printf("Texto Original: ");
    for (int i = 0; i < 8; ++i)
    {
        printf("%c ", orgText[i]);
    }
    printf("\n");
    system("pause");
    printf("\n");
    return 0;
}
