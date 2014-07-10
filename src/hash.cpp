#include "hash.h"

inline uint32_t ROTL32 ( uint32_t x, int8_t r )
{
    return (x << r) | (x >> (32 - r));
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash)
{
    // The following is MurmurHash3 (x86_32), see http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
    uint32_t h1 = nHashSeed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int nblocks = vDataToHash.size() / 4;

    //----------
    // body
    const uint32_t * blocks = (const uint32_t *)(&vDataToHash[0] + nblocks*4);

    for(int i = -nblocks; i; i++)
    {
        uint32_t k1 = blocks[i];

        k1 *= c1;
        k1 = ROTL32(k1,15);
        k1 *= c2;

        h1 ^= k1;
        h1 = ROTL32(h1,13); 
        h1 = h1*5+0xe6546b64;
    }

    //----------
    // tail
    const uint8_t * tail = (const uint8_t*)(&vDataToHash[0] + nblocks*4);

    uint32_t k1 = 0;

    switch(vDataToHash.size() & 3)
    {
    case 3: k1 ^= tail[2] << 16;
    case 2: k1 ^= tail[1] << 8;
    case 1: k1 ^= tail[0];
            k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
    };

    //----------
    // finalization
    h1 ^= vDataToHash.size();
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_ULONG_LE
#define GET_ULONG_LE(n, b, i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ]       )        \
        | ( (unsigned long) (b)[(i) + 1] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 2] << 16 )        \
        | ( (unsigned long) (b)[(i) + 3] << 24 );       \
}
#endif
 
#ifndef PUT_ULONG_LE
#define PUT_ULONG_LE(n, b, i)                           \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
}
#endif
 
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
 
/*
 * Implementation of RTR0 cryptographic hash function
 * Example: RTR0((uint8_t*)message, length, result);
 */ 
void RTR0(const uint8_t *initial_message, size_t initial_length, uint8_t *result)
{
    /* Declaration of variables */
    size_t length, offset, i;
 
    /* Declaration of message */
    uint8_t *message = NULL; 
 
    /* Declaration of algorithm values */
    uint32_t words[17];
    uint32_t sand;
    uint32_t A = 0xf7537e82, B = 0xbd3af235, C = 0x2ad7d2bb, D = 0xeb86d391, E = 0xd76aa478, S;
 
    /* Calculate new length */
    for (length = initial_length + 1; length % (512 / 8) != 448 / 8; length++)
        ;
 
    /* Prepare message */
    message = (uint8_t*) malloc(length + 16);
 
    /* Copy block of memory */
    memcpy(message, initial_message, initial_length);
 
    /* Append "1" bit */
    message[initial_length] = 0x80;
 
    /* Append "0" bits */
    for (offset = initial_length + 1; offset < length + 16; offset++)
        message[offset] = 0;
 
    /* Append the len in bits at the end of the buffer */
    PUT_ULONG_LE(initial_length * 8, message + length, 0);
 
    /* Initial_len >> 29 == initial_len * 8 >> 32, but avoids overflow */
    PUT_ULONG_LE(initial_length >> 29, message + length + 4, 0);
 
    /* Process the message in successive 512-bit chunks */
    for(offset = 0; offset < length; offset += (512 / 8))
    { 
        for (i = 0; i <= 16; i++)
        {
            /* Get little endian */
            GET_ULONG_LE(words[i], message + offset + i * 4, 0);
        }
 
        for (i = 1; i <= 16; i++)
        {
            /* Combining depending with neighbour value */
            words[i] ^= words[i-1] << 1 | i;
 
            /* Calculate sand for rotated values */
            sand = LEFTROTATE(words[i], words[i-1]) ^ RIGHTROTATE(words[i-1], words[i]);

            /* Addition sand to the appropriate drawers */
            if( i % 4 == 0 )
                A += sand;
            if( i % 4 == 1 )
                B += sand;
            if( i % 4 == 2 )
                C += sand;
            if( i % 4 == 3 )
                D += sand;

            E += sand;
        }
 
        /* Calculate checksum for final values */
        S = A << B ^ C >> D;
        S += words[16] ^ E;
 
        /* Addition checksum to the appropriate drawers */
        A = A ^ S;
        B = B ^ S;
        C = C ^ S;
        D = D ^ S;
        E = E ^ S;
    }

    /* Releasing memory */
    free(message);
 
    /* Returns 160-bit (20-byte) final hash in table */
    PUT_ULONG_LE(A, result, 0);
    PUT_ULONG_LE(B, result + 4, 0);
    PUT_ULONG_LE(C, result + 8, 0);
    PUT_ULONG_LE(D, result + 12, 0);
    PUT_ULONG_LE(E, result + 16, 0);
}
