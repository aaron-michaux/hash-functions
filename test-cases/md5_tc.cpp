
#include "md5.hpp"

#define CATCH_CONFIG_PREFIX_ALL
#include "catch.hpp"

CATCH_TEST_CASE("Md5Sum_", "[md5_sum]")
{
   static_assert(std::is_nothrow_move_constructible<MD5>::value,
                 "MD5 should be noexcept MoveConstructible");

   //
   // -------------------------------------------------------
   //
   CATCH_SECTION("md5")
   {
      auto test_str = [&](const std::string& s, const std::string& val) {
         CATCH_REQUIRE(md5(s) == val);
      };

      test_str("The rain in Spain falls mainly on the plains.",
               "a7a5a692ff3af6078c52465015dbebba");

      std::array<char, 30> dat{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                0x16, 0x17, 0x18, 0x30, 0x31, 0x30, 0x32, 0x33,
                                0x34, 0x35, 0x36, 0x37, 0x38, 0x39}};
      const std::string digest = "3271e81510b4854cff43e57b103d3dd1";

      {
         MD5 m;
         m.append(&dat[0], dat.size());

         CATCH_REQUIRE(m.hexdigest() == digest);
      }
   }
}
