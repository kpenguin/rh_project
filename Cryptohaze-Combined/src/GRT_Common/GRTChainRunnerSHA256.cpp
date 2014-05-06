


#include "GRT_Common/GRTChainRunnerSHA256.h"
#include "GRT_Common/GRTTableHeader.h"
#include <stdlib.h>

#include "CUDA_Common/CUDA_SHA256.h"

// Hash output: 32 bytes.
// Hash input block: 64 bytes

GRTChainRunnerSHA256::GRTChainRunnerSHA256() : GRTChainRunner(32, 64) {

}

void GRTChainRunnerSHA256::hashFunction(unsigned char *hashInput, unsigned char *hashOutput) {
    // 32-bit unsigned values for the hash
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15;

    int length = this->TableHeader->getPasswordLength();

    // 32-bit accesses to the hash arrays
    uint32_t *InitialArray32;
    uint32_t *OutputArray32;
    InitialArray32 = (uint32_t *) hashInput;
    OutputArray32 = (uint32_t *) hashOutput;

	

    b0 = (uint32_t) InitialArray32[0];
    b1 = (uint32_t) InitialArray32[1];
    b2 = (uint32_t) InitialArray32[2];
    b3 = (uint32_t) InitialArray32[3];
    b4 = (uint32_t) InitialArray32[4];
    b5 = (uint32_t) InitialArray32[5];
    b6 = (uint32_t) InitialArray32[6];
    b7 = (uint32_t) InitialArray32[7];
    b8 = (uint32_t) InitialArray32[8];
    b9 = (uint32_t) InitialArray32[9];
    b10 = (uint32_t) InitialArray32[10];
    b11 = (uint32_t) InitialArray32[11];
    b12 = (uint32_t) InitialArray32[12];
    b13 = (uint32_t) InitialArray32[13];
    b14 = (uint32_t) InitialArray32[14];

	//debug printf("Original Plaintext: %c%c%c%c%c%c\n", (b0 & 0xff), (b0 >> 8) & 0xff, (b0 >> 16) & 0xff, (b0 >> 24 & 0xff), b1 & 0xff, (b1 >> 8) & 0xff);
	
    switch (length) {
        case 0:
            b0 |= 0x00000080;
            break;
        case 1:
            b0 |= 0x00008000;
            break;
        case 2:
            b0 |= 0x00800000;
            break;
        case 3:
            b0 |= 0x80000000;
            break;
        case 4:
            b1 |= 0x00000080;
            break;
        case 5:
            b1 |= 0x00008000;
            break;
        case 6:
            b1 |= 0x00800000;
            break;
        case 7:
            b1 |= 0x80000000;
            break;
        case 8:
            b2 |= 0x00000080;
            break;
        case 9:
            b2 |= 0x00008000;
            break;
        case 10:
            b2 |= 0x00800000;
            break;
        case 11:
            b2 |= 0x80000000;
            break;
        case 12:
            b3 |= 0x00000080;
            break;
        case 13:
            b3 |= 0x00008000;
            break;
        case 14:
            b3 |= 0x00800000;
            break;
        case 15:
            b3 |= 0x80000000;
            break;
        case 16:
            b4 |= 0x00000080;
            break;
        case 17:
            b4 |= 0x00008000;
            break;
        case 18:
            b4 |= 0x00800000;
            break;
        case 19:
            b4 |= 0x80000000;
            break;
        default:
            printf("Length %d not supported!\n", length);
            exit(1);
    }

    b15 = ((length * 8) & 0xff) << 24 | (((length * 8) >> 8) & 0xff) << 16;

	// Debug
	/*
    printf("b0 : %08x\t", b0);
    printf("b1 : %08x\t", b1);
    printf("b2 : %08x\t", b2);
    printf("b3 : %08x\t", b3);
    printf("b4 : %08x\t", b4);
    printf("b5 : %08x\t", b5);
    printf("b6 : %08x\t", b6);
    printf("b7 : %08x\t", b7);
    printf("b8 : %08x\t", b8);
    printf("b9 : %08x\t", b9);
    printf("b10: %08x\t", b10);
    printf("b11: %08x\t", b11);
    printf("b12: %08x\t", b12);
    printf("b13: %08x\t", b13);
    printf("b14: %08x\t", b14);
    printf("b15: %08x\t\n", b15);

    printf("a\t b\t c\t d\t e\t f\t g\t h\n");
    printf("%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\n", a, b, c, d, e, f, g, h);
	*/

	SHA256_FIRST_BLOCK();
	
    a = reverse(a);
    b = reverse(b);
    c = reverse(c);
    d = reverse(d);
    e = reverse(e);
    f = reverse(f);
    g = reverse(g);
    h = reverse(h);

	// Debug
	/*
	printf("a: %08x\n", a);
    printf("b: %08x\n", b);
    printf("c: %08x\n", c);
    printf("d: %08x\n", d);
    printf("e: %08x\n", e);
    printf("f: %08x\n", f);
    printf("g: %08x\n", g);
    printf("h: %08x\n", h);
	*/
	
    OutputArray32[0] = a;
    OutputArray32[1] = b;
    OutputArray32[2] = c;
    OutputArray32[3] = d;
    OutputArray32[4] = e;
    OutputArray32[5] = f;
    OutputArray32[6] = g;
    OutputArray32[7] = h;
}

void GRTChainRunnerSHA256::reduceFunction(unsigned char *password, unsigned char *hash, uint32_t CurrentStep) {
    UINT4 a, b, c, d;

    uint32_t charset_offset = CurrentStep % this->charsetLength;
    uint32_t PasswordLength = this->TableHeader->getPasswordLength();
    uint32_t Device_Table_Index = this->TableHeader->getTableIndex();

    a = (hash[3]*(256*256*256) + hash[2]*(256*256) + hash[1]*256 + hash[0]);
    b = (hash[7]*(256*256*256) + hash[6]*(256*256) + hash[5]*256 + hash[4]);
    c = (hash[11]*(256*256*256) + hash[10]*(256*256) + hash[9]*256 + hash[8]);
    d = (hash[15]*(256*256*256) + hash[14]*(256*256) + hash[13]*256 + hash[12]);

    UINT4 z;
    // Reduce it
    // First 3
    z = (UINT4)(a+CurrentStep+Device_Table_Index) % (256*256*256);
    password[0] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 1) {return;}
    z /= 256;
    password[1] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 2) {return;}
    z /= 256;
    password[2] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 3) {return;}

    // Second 3
    z = (UINT4)(b+CurrentStep+Device_Table_Index) % (256*256*256);
    password[3] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 4) {return;}
    z /= 256;
    password[4] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 5) {return;}
    z /= 256;
    password[5] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 6) {return;}

    z = (UINT4)(c+CurrentStep+Device_Table_Index) % (256*256*256);
    password[6] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 7) {return;}
    z /= 256;
    password[7] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 8) {return;}
    z /= 256;
    password[8] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 9) {return;}

    z = (UINT4)(d+CurrentStep+Device_Table_Index) % (256*256*256);
    password[9] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 10) {return;}
    z /= 256;
    password[10] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 11) {return;}
    z /= 256;
    password[11] = (UINT4)this->charset[(z % 256) + charset_offset];
    if (PasswordLength == 12) {return;}

}
