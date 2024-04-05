// Copyright© 2021 AncientTides 


#ifndef GRADA_SHA256_H
#define GRADA_SHA256_H

#include <string>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
// #include "grada_endian_reverse.h" // for hash reversal
#include <assert.h>

using std::string;
using std::stringstream;
using std::hex;
using std::vector;

// inline std::string sha256(std::string input);
// std::string hex_sha256(std::string input);
typedef vector<std::uint8_t> Bytes;


inline std::string ParseHex(std::string& s)
{
    assert(s.size() % 2 == 0);
    static const std::size_t symbol_count = 256;
    static const unsigned char hex_to_bin[symbol_count] = 
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x00 - 0x07
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08 - 0x0F
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x10 - 0x17
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x18 - 0x1F
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20 - 0x27
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x28 - 0x2F
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 0x30 - 0x37
        0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x38 - 0x3F
        0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, // 0x40 - 0x47
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x48 - 0x4F
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x50 - 0x57
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x58 - 0x5F
        0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, // 0x60 - 0x67
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x68 - 0x6F
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x70 - 0x77
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x78 - 0x7F
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x80 - 0x87
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88 - 0x8F
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90 - 0x97
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x98 - 0x9F
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA0 - 0xA7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA8 - 0xAF
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xB0 - 0xB7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xB8 - 0xBF
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC0 - 0xC7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC8 - 0xCF
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD0 - 0xD7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD8 - 0xDF
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE0 - 0xE7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE8 - 0xEF
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF0 - 0xF7
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 0xF8 - 0xFF
    };

    std::string out;
    auto itr = s.begin();
    while (itr != s.end())
    {
       unsigned char b = static_cast<unsigned char>(hex_to_bin[*(itr++)] << 4);
       b |= static_cast<unsigned char>(hex_to_bin[*(itr++)]     );
       out.push_back(b);
    }
    return out;
}


//      ----------------        SHA256 ALGORITHM        ------------------


typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

static const unsigned int SHA224_256_BLOCK_SIZE = (64); //(512/8);
void init();
// void transform_T(const unsigned char *message, unsigned int block_nb);
void update(const unsigned char *message, unsigned int len);
void final(unsigned char *digest);
static const unsigned int DIGEST_SIZE = (32);

void transform(const unsigned char *message, unsigned int block_nb);
unsigned int m_tot_len;
unsigned int m_len;
unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
uint32 m_h[8];

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32_t) *((str) + 3)      )    \
           | ((uint32_t) *((str) + 2) <<  8)    \
           | ((uint32_t) *((str) + 1) << 16)    \
           | ((uint32_t) *((str) + 0) << 24);   \
}

//          ---------------      DEFINITIONS ARC        --------------------------
//UL = uint32
const unsigned int sha256_k[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void transform(const unsigned char *message, unsigned int block_nb)
{
    uint32_t w[64]; // 64
    uint32_t wv[8];
    uint32_t t1, t2;
    const unsigned char *sub_block;
    for (int i = 0; i < (int) block_nb; i++)
    {
        sub_block = message + (i << 6);

        for (int j = 0; j < 16; j++) // 16
            SHA2_PACK32(&sub_block[j << 2], &w[j]);

        for (int x = 16; x < 64; x++) // 64
            w[x] =  SHA256_F4(w[x -  2]) + w[x -  7] + SHA256_F3(w[x - 15]) + w[x - 16];

        for (int d = 0; d < 8; d++) // 8
            wv[d] = m_h[d];

        for (int h = 0; h < 64; h++) // 64
        {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6]) + sha256_k[h] + w[h];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (int q = 0; q < 8; q++) // 8
            m_h[q] += wv[q];
    }
}


void init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}


void update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);

    if (m_len + len < SHA224_256_BLOCK_SIZE)
    {
        m_len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}

void final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9) < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);

    for (int f = 0 ; f < 8; f++)
        SHA2_UNPACK32(m_h[f], &digest[f << 2]);

    //  string dd = ""; // String variable to store digest data
    //  Added loop
    //  for (int i = 0; i < sizeof(digest); i++) // for elements in char array
    //      dd = digest[i]; // store elements in string variable "stringData"
    //  return dd;
}



inline std::string sha256(std::string input)
{
    unsigned char digest[32];
    memset(digest,0,32);
   
    init();
    update( (unsigned char*)input.c_str(), input.length());
    final(digest);

    char buf[2*32+1];
    buf[2*32] = 0;
    for (int i = 0; i < 32; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return std::string(buf);
}


inline std::string hex_sha256(std::string input)
{    
    unsigned char hash[32];// header_data is "160" in size because midstate optimization is not implemented
    char buf[2*32+1];
    buf[2*32] = 0;

    input = ParseHex(input); // ParseHex() is UNDEFINED !!!
    init(); // Initiialize
    update((unsigned char*)input.c_str(), input.length()); // Update
    final(hash); // Finalize

    // Uncomment code below if you want to directly double hash input data using a single "sha256(input)" function call
    // init();
    // update(hash, 32);
    // final(hash);

    for (int i = 0; i < 32; i++) 
        sprintf(buf+i*2, "%02x", hash[i]); // feed data from hash into buf and format data

    return std::string(buf); // Return buf as string instead of char
}



inline std::string double_Hex_sha256(std::string input)
{    
    unsigned char hash[32];// header_data is "160" in size because midstate optimization is not implemented
    char buf[2*32+1];
    buf[2*32] = 0;

    input = ParseHex(input); // ParseHex() is UNDEFINED !!!
    init(); // Initiialize
    update((unsigned char*)input.c_str(), input.length()); // Update
    final(hash); // Finalize

    // Uncomment code below if you want to directly double hash input data using a single "sha256(input)" function call
    init();
    update(hash, 32);
    final(hash);

    for (int i = 0; i < 32; i++) 
        sprintf(buf+i*2, "%02x", hash[i]); // feed data from hash into buf and format data

    return std::string(buf); // Return buf as string instead of char
}


#endif


