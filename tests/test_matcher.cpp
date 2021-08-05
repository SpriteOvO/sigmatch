//
// Copyright 2021 SpriteOvO
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "includes.hpp"

using namespace sigmatch;
using namespace sigmatch_literals;

TEST_CASE("Matcher type traits", "[matcher]")
{
    STATIC_REQUIRE(is_copy_move_able_v<matcher>);
}

TEST_CASE("Signature matcher one time", "[matcher]")
{
    signature sig = "23 3b 5? d9 e3"_sig;

    // matched test
    {
        matcher matcher_{sig};

        std::vector<const std::byte *> result;

        std::vector<std::byte> vbytes = {
            std::byte{0x23}, std::byte{0x3B}, std::byte{0x57}, std::byte{0xD9}, std::byte{0xE3}};

        matcher_.match(std::span{vbytes}, vbytes.data(), result);
        REQUIRE(result.size() == 1);
        REQUIRE(result[0] == vbytes.data());
    }

    // mismatched test
    {
        matcher matcher_{sig};

        std::vector<const std::byte *> result;

        std::vector<std::byte> vbytes = {
            std::byte{0x23}, std::byte{0x3B}, std::byte{0x47}, std::byte{0xD9}, std::byte{0xE3}};

        matcher_.match(std::span{vbytes}, vbytes.data(), result);
        REQUIRE(result.empty());
    }
}

TEST_CASE("Signature matcher multiple times", "[matcher]")
{
    signature sig = "91 5e a* 4e ?? 2a 4d"_sig;

    // matched test
    {
        matcher matcher_{sig};

        std::vector<const std::byte *> result;

        std::vector<std::byte> vbytes = {std::byte{0x91}, std::byte{0x5E}, std::byte{0xA9},
                                         std::byte{0x4E}, std::byte{0x69}, std::byte{0x2A},
                                         std::byte{0x4D}};

        matcher_.match(std::span{vbytes.begin(), 1}, vbytes.data(), result);
        REQUIRE(result.empty());

        matcher_.match(std::span{vbytes.begin() + 1, 2}, vbytes.data() + 1, result);
        REQUIRE(result.empty());

        matcher_.match(std::span{vbytes.begin() + 3, 1}, vbytes.data() + 3, result);
        REQUIRE(result.empty());

        matcher_.match(std::span{vbytes.begin() + 4, 3}, vbytes.data() + 4, result);
        REQUIRE(result.size() == 1);
        REQUIRE(result[0] == vbytes.data());
    }

    // mismatched test
    {
        matcher matcher_{sig};

        std::vector<const std::byte *> result;

        //                                            v mismatched value
        std::vector<std::byte> vbytes = {std::byte{0x92}, std::byte{0x5E}, std::byte{0xA9},
                                         std::byte{0x4E}, std::byte{0x69}, std::byte{0x2A},
                                         std::byte{0x4D}};

        matcher_.match(std::span{vbytes.begin(), 1}, vbytes.data(), result);
        REQUIRE(result.empty());

        matcher_.match(std::span{vbytes.begin() + 1, 2}, vbytes.data() + 1, result);
        REQUIRE(result.empty());

        matcher_.match(std::span{vbytes.begin() + 3, 1}, vbytes.data() + 3, result);
        REQUIRE(result.empty());

        matcher_.match(std::span{vbytes.begin() + 4, 3}, vbytes.data() + 4, result);
        REQUIRE(result.empty());
    }
}
