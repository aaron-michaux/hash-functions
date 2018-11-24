
#include "sha256.hpp"

#define CATCH_CONFIG_PREFIX_ALL
#include "catch.hpp"

CATCH_TEST_CASE("Sha256Sum_", "[sha256_sum]")
{
   //
   // -------------------------------------------------------
   //
   CATCH_SECTION("sha256")
   {
      auto test_str = [&](const std::string& s, const std::string& val) {
         CATCH_REQUIRE(sha256(s) == val);
      };

      test_str(
          "The rain in Spain falls mainly on the plains.\n",
          "272c192d765b73b7ed495d9574ffccdbeb6c70d8fa5f5f2476788e8f083b549e");

      test_str(
          "",
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

      std::array<char, 30> dat{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                0x16, 0x17, 0x18, 0x30, 0x31, 0x30, 0x32, 0x33,
                                0x34, 0x35, 0x36, 0x37, 0x38, 0x39}};
      const std::string digest
          = "940f839bafb03906b28ce910f83119d8a01f9314da5146508f4361f7d6fe9474";

      {
         Sha256 m;
         m.append(&dat[0], dat.size());
         CATCH_REQUIRE(m.hexdigest() == digest);
      }
   }
}
