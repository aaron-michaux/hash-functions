/* MD5

   converted by Aaron Michaux (aaron@pageofswords.net)
   to improve the clarity and C++iness of the interface

   based on:

   converted to C++ class by Frank Thilo (thilo@unix-ag.org)
   for bzflag (http://www.bzflag.org)

   based on:

   md5.h and md5.c
   reference implementation of RFC 1321

   Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
   rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD5 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD5 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.

*/

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

// a small class for calculating MD5 hashes of strings or byte arrays
// it is not meant to be fast or secure
//
// usage: 1) feed data with append()
//        2) get hexdigest() string
//      or
//           MD5(std::string).hexdigest()
//
// assumes that char is 8 bit and int is 32 bit
class MD5
{
 public:
   MD5();
   MD5(const std::string& text);

   void append(const std::string& text);
   void append(const unsigned char* buf, size_t length);
   void append(const char* buf, size_t length);
   void append(const void* buf, size_t length);

   std::string hexdigest();
   std::string hexdigest() const;

   size_t digest_size() const noexcept; // in bytes
   void get_digest(unsigned char hash[16]) const;
   std::array<unsigned char, 16> get_digest() const;

   // Finish called automatically
   MD5& finish();

 private:
   static constexpr int blocksize = 64;

   uint8_t buffer_[blocksize]; // bytes that didn't fit in last 64 byte chunk
   uint32_t count_[2];         // 64bit counter for number of bits (lo, hi)
   uint32_t state_[4];         // digest so far
   uint8_t digest_[16];        // the result

   bool finalized_{false};

   void init_();
   void transform_(const uint8_t block[blocksize]);
};

std::string md5(const std::string str);

inline std::ostream& operator<<(std::ostream& o, MD5 hash)
{
   o << hash.hexdigest();
   return o;
}
