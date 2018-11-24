
/*********************************************************************
 * Code adapted by Aaron Michaux (aaron@pageofswords.net) From:
 *
 * Filename:   sha256.c
 * Author:     Brad Conte (brad AT bradconte.com)
 * Copyright:
 * Disclaimer: This code is presented "as is" without any guarantees.
 * Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
              *
http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/

#include "sha256.hpp"

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <memory.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32 // SHA256 outputs a 32 byte digest

/****************************** MACROS ******************************/
//#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const uint32_t k[64]
    = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
       0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
       0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
       0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
       0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
       0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
       0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
       0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
       0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*********************** FUNCTION DEFINITIONS ***********************/
void Sha256::transform_() noexcept
{
   WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

   for(i = 0, j = 0; i < 16; ++i, j += 4)
      m[i] = WORD((data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8)
                  | (data[j + 3]));
   for(; i < 64; ++i)
      m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

   a = state[0];
   b = state[1];
   c = state[2];
   d = state[3];
   e = state[4];
   f = state[5];
   g = state[6];
   h = state[7];

   for(i = 0; i < 64; ++i) {
      t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
      t2 = EP0(a) + MAJ(a, b, c);
      h  = g;
      g  = f;
      f  = e;
      e  = d + t1;
      d  = c;
      c  = b;
      b  = a;
      a  = t1 + t2;
   }

   state[0] += a;
   state[1] += b;
   state[2] += c;
   state[3] += d;
   state[4] += e;
   state[5] += f;
   state[6] += g;
   state[7] += h;
}

void Sha256::init_() noexcept
{
   datalen  = 0;
   bitlen   = 0;
   state[0] = 0x6a09e667;
   state[1] = 0xbb67ae85;
   state[2] = 0x3c6ef372;
   state[3] = 0xa54ff53a;
   state[4] = 0x510e527f;
   state[5] = 0x9b05688c;
   state[6] = 0x1f83d9ab;
   state[7] = 0x5be0cd19;
}

void Sha256::update(const BYTE dat[], size_t len) noexcept
{
   WORD i;

   for(i = 0; i < len; ++i) {
      this->data[datalen] = dat[i];
      datalen++;
      if(datalen == 64) {
         transform_();
         bitlen += 512;
         datalen = 0;
      }
   }
}

void Sha256::final(BYTE hash[]) noexcept
{
   WORD i;

   i = datalen;

   // Pad whatever data is left in the buffer.
   if(datalen < 56) {
      data[i++] = 0x80;
      while(i < 56) data[i++] = 0x00;
   } else {
      data[i++] = 0x80;
      while(i < 64) data[i++] = 0x00;
      transform_();
      memset(data, 0, 56);
   }

   // Append to the padding the total message's length in bits and transform.
   bitlen += datalen * 8;
   data[63] = static_cast<BYTE>(bitlen);
   data[62] = static_cast<BYTE>(bitlen >> 8);
   data[61] = static_cast<BYTE>(bitlen >> 16);
   data[60] = static_cast<BYTE>(bitlen >> 24);
   data[59] = static_cast<BYTE>(bitlen >> 32);
   data[58] = static_cast<BYTE>(bitlen >> 40);
   data[57] = static_cast<BYTE>(bitlen >> 48);
   data[56] = static_cast<BYTE>(bitlen >> 56);
   transform_();

   // Since this implementation uses little endian byte ordering and SHA uses
   // big endian, reverse all the bytes when copying the final state to the
   // output hash.
   for(i = 0; i < 4; ++i) {
      hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
      hash[i + 28] = (state[7] >> (24 - i * 8)) & 0x000000ff;
   }
}

//  --------------------------------------------------------------- Construction

// default ctor, just initailize
Sha256::Sha256() noexcept { init_(); }
Sha256::Sha256(std::string_view text) noexcept
{
   init_();
   append(text.data(), text.length());
   finish();
}

// ---------------------------------------------------------------------- append

void Sha256::append(std::string_view text) noexcept
{
   append(text.data(), text.size());
}

void Sha256::append(const unsigned char* input, size_t length) noexcept
{
   update(input, length);
}

void Sha256::append(const char* input, size_t length) noexcept
{
   append(reinterpret_cast<const void*>(input), length);
}

void Sha256::append(const void* buf, size_t length) noexcept
{
   append(reinterpret_cast<const unsigned char*>(buf), length);
}

// ---------------------------------------------------------------------- finish

Sha256& Sha256::finish() noexcept
{
   if(!finalized_) {
      final(digest_);
      finalized_ = true;
   }

   return *this;
}

// -----------------------------------------------------------------------------

size_t Sha256::digest_size() const noexcept { return SHA256_BLOCK_SIZE; }

void Sha256::get_digest(uint8_t hash[32]) const noexcept
{
   // To make type "thread-compatible", Don't lazy-finish,
   assert(finalized_); // You must call finish() before getting the digest
   memcpy(hash, digest_, 32);
}

std::vector<uint8_t> Sha256::get_digest() const noexcept
{
   std::vector<uint8_t> hash(32);
   get_digest(&hash[0]);
   return hash;
}

// -----------------------------------------------------------------------------

std::string Sha256::hexdigest() noexcept
{
   if(!finalized_) finish();
   return static_cast<const Sha256*>(this)->hexdigest();
}

std::string Sha256::hexdigest() const noexcept
{
   uint8_t hash[32];
   get_digest(hash);

   char buf[65];
   for(int i = 0; i < 32; i++) sprintf(buf + i * 2, "%02x", hash[i]);
   buf[64] = 0;

   return std::string(buf);
}

// -----------------------------------------------------------------------------

std::string sha256(std::string_view str) noexcept
{
   Sha256 sha;
   sha.append(str);
   return sha.hexdigest();
}
