
#include <iostream>

#include "md5.hpp"
#include "sha256.hpp"

static const std::string data("Data to hash.");

template<typename T> std::string hash_value()
{
   T hash;
   hash.append(data);
   hash.append("You can continue to append more data.");
   return hash.hexdigest();
}

int main(int, char**)
{
   std::cout << "\nhash-functions example.\n\n";

   std::cout << "   MD5 digest:    " << hash_value<MD5>() << "\n";
   std::cout << "   Sha256 digest: " << hash_value<Sha256>() << "\n";
   std::cout << std::endl;

   return EXIT_SUCCESS;
}
