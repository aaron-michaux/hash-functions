
# hash functions

There is code kicking around the internet for the [sha256](https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c) and [md5](https://github.com/google/jsonnet/blob/master/third_party/md5/md5.cpp) hashing algorithms. With thanks to the original developers, I've modified the code to improve the interface somewhat, and also to be more standards compliant.

## testing

Requires `gcc-7`. Edit the `CC` variable in the `Makefile` to change compiler. Works with recent versions of `clang` as well.

```
make test
./test
```
## example

```
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

```

Output:

```
hash-functions example.

   MD5 digest:    3ce726ece4dfa2dc4206a92fcda92c8b
   Sha256 digest: fba7d1847458e31310a20c05d943377d6c45232bba304336167ba3c6e108ea96

```
