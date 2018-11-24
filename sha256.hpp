
#pragma once

#include <string>
#include <type_traits>
#include <vector>

class Sha256
{
 public:
   Sha256();
   Sha256(const std::string& text);

   void append(const std::string& text);
   void append(const unsigned char* buf, size_t length);
   void append(const char* buf, size_t length);
   void append(const void* buf, size_t length);

   std::string hexdigest();
   std::string hexdigest() const;

   size_t digest_size() const noexcept; // in bytes
   void get_digest(uint8_t hash[32]) const;
   std::vector<uint8_t> get_digest() const;

   // Finish called automatically
   Sha256& finish();

 private:
   using BYTE = uint8_t;
   using WORD = uint32_t;

   BYTE data[64];
   WORD datalen;
   uint64_t bitlen;
   WORD state[8];
   BYTE digest_[32];
   bool finalized_ = false;

   void transform_();
   void init_();
   void update(const BYTE dat[], size_t len);
   void final(BYTE hash[]);
};

std::string sha256(const std::string str);

inline std::ostream& operator<<(std::ostream& o, Sha256 hash)
{
   o << hash.hexdigest();
   return o;
}
