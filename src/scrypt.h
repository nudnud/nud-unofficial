#ifndef SCRYPT_H
#define SCRYPT_H
#include <stdlib.h>
#include <stdint.h>

#include <string>

static const int SCRYPT_SCRATCHPAD_SIZE = 131072 + 63;

void scrypt_1024_1_1_256(const char *input, char *output);
void scrypt_1024_1_1_256_sp_generic(const char *input, char *output, char *scratchpad);

#if defined(USE_SSE2)
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_AMD64) || (defined(MAC_OSX) && defined(__i386__))
#define USE_SSE2_ALWAYS 1
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_sse2((input), (output), (scratchpad))
#else
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_detected((input), (output), (scratchpad))
#endif

void scrypt_detect_sse2();
void scrypt_1024_1_1_256_sp_sse2(const char *input, char *output, char *scratchpad);
extern void (*scrypt_1024_1_1_256_sp_detected)(const char *input, char *output, char *scratchpad);
#else
#define scrypt_1024_1_1_256_sp(input, output, scratchpad) scrypt_1024_1_1_256_sp_generic((input), (output), (scratchpad))
#endif

void
PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
    size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen);

static inline uint32_t le32dec(const void *pp)
{
        const uint8_t *p = (uint8_t const *)pp;
        return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
            ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void *pp, uint32_t x)
{
        uint8_t *p = (uint8_t *)pp;
        p[0] = x & 0xff;
        p[1] = (x >> 8) & 0xff;
        p[2] = (x >> 16) & 0xff;
        p[3] = (x >> 24) & 0xff;
}

#ifndef __GNUC__
#undef __const
#define __const const
#endif

typedef unsigned int BF_word;
typedef signed int BF_word_signed;

#ifndef __SKIP_GNU
extern char *bcrypt_crypt(__const char *key, __const char *setting);
extern char *crypt_r(__const char *key, __const char *setting, void *data);
#endif

#ifndef __SKIP_OW
extern char *crypt_rn(__const char *key, __const char *setting,
        void *data, int size);
extern char *crypt_ra(__const char *key, size_t length, __const char *setting,
        void **data, int *size);
extern char *crypt_gensalt(__const char *prefix, unsigned long count,
        __const char *input, int size);
extern char *crypt_gensalt_rn(__const char *prefix, unsigned long count,
        __const char *input, int size, char *output, int output_size);
extern char *crypt_gensalt_ra(__const char *prefix, unsigned long count,
        __const char *input, int size);
#endif

extern unsigned char _crypt_itoa64[];
extern char *_crypt_gensalt_traditional_rn(const char *prefix,
        unsigned long count,
        const char *input, int size, char *output, int output_size);
extern char *_crypt_gensalt_extended_rn(const char *prefix,
        unsigned long count,
        const char *input, int size, char *output, int output_size);
extern char *_crypt_gensalt_md5_rn(const char *prefix, unsigned long count,
        const char *input, int size, char *output, int output_size);

extern int _crypt_output_magic(const char *setting, char *output, int size);
extern char *_crypt_blowfish_rn(const char *key, size_t length,
	const char *setting, char *output, int size);
extern char *_crypt_gensalt_blowfish_rn(const char *prefix,
        unsigned long count,
        const char *input, int size, char *output, int output_size);

extern int BF_decode(BF_word *dst, const char *src, int size);

extern std::string bcrypt_iterated(std::string const& input);

#endif
