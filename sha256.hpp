
#pragma once

#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

class Sha256
{
 public:
   Sha256() noexcept;
   Sha256(std::string_view text) noexcept;

   void append(std::string_view text) noexcept;
   void append(const unsigned char* buf, size_t length) noexcept;
   void append(const char* buf, size_t length) noexcept;
   void append(const void* buf, size_t length) noexcept;

   std::string hexdigest() noexcept;
   std::string hexdigest() const noexcept;

   size_t digest_size() const noexcept; // in bytes
   void get_digest(uint8_t hash[32]) const noexcept;
   std::vector<uint8_t> get_digest() const noexcept;

   // Finish called automatically
   Sha256& finish() noexcept;

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
   void update(const BYTE dat[], size_t len) noexcept;
   void final(BYTE hash[]) noexcept;
};

std::string sha256(std::string_view str) noexcept;

inline std::ostream& operator<<(std::ostream& o, Sha256 hash)
{
   o << hash.hexdigest();
   return o;
}
