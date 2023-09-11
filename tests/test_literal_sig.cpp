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

#define SIGMATCH_ENABLE_SIGNATURE_RUNTIME_PARSING

#include "includes.hpp"

using namespace sigmatch;
using namespace sigmatch_literals;

TEST_CASE("Signature type traits", "[signature]")
{
    STATIC_REQUIRE(is_copy_move_able_v<signature>);
}

TEST_CASE("Literal signature bytes", "[signature]")
{
    auto sig = "  1A Bb ?C  4?  *d  ?? ** 99     "_sig;
    const auto &sig_bytes = sig.bytes();

    REQUIRE(sig.size() == 8);
    REQUIRE(sig_bytes.size() == 8);

    REQUIRE(sig_bytes[0].value() == std::byte{0x1A});
    REQUIRE(sig_bytes[0].mask() == std::byte{0xFF});
    REQUIRE(sig_bytes[0].match(std::byte{0x1A}));
    REQUIRE(!sig_bytes[0].match(std::byte{0x2A}));
    REQUIRE(!sig_bytes[0].match(std::byte{0x1B}));

    REQUIRE(sig_bytes[1].value() == std::byte{0xBB});
    REQUIRE(sig_bytes[1].mask() == std::byte{0xFF});
    REQUIRE(sig_bytes[1].match(std::byte{0xBB}));
    REQUIRE(!sig_bytes[1].match(std::byte{0xC2}));
    REQUIRE(!sig_bytes[1].match(std::byte{0xB3}));

    REQUIRE(sig_bytes[2].value() == std::byte{0x0C});
    REQUIRE(sig_bytes[2].mask() == std::byte{0x0F});
    REQUIRE(sig_bytes[2].match(std::byte{0x1C}));
    REQUIRE(sig_bytes[2].match(std::byte{0xAC}));
    REQUIRE(!sig_bytes[2].match(std::byte{0x1B}));
    REQUIRE(!sig_bytes[2].match(std::byte{0xC2}));

    REQUIRE(sig_bytes[3].value() == std::byte{0x40});
    REQUIRE(sig_bytes[3].mask() == std::byte{0xF0});
    REQUIRE(sig_bytes[3].match(std::byte{0x42}));
    REQUIRE(sig_bytes[3].match(std::byte{0x4B}));
    REQUIRE(!sig_bytes[3].match(std::byte{0x27}));
    REQUIRE(!sig_bytes[3].match(std::byte{0xD9}));

    REQUIRE(sig_bytes[4].value() == std::byte{0x0D});
    REQUIRE(sig_bytes[4].mask() == std::byte{0x0F});
    REQUIRE(sig_bytes[4].match(std::byte{0x1D}));
    REQUIRE(sig_bytes[4].match(std::byte{0xAD}));
    REQUIRE(!sig_bytes[4].match(std::byte{0x1B}));
    REQUIRE(!sig_bytes[4].match(std::byte{0xC2}));

    REQUIRE(sig_bytes[5].value() == std::byte{0x00});
    REQUIRE(sig_bytes[5].mask() == std::byte{0x00});
    REQUIRE(sig_bytes[5].match(std::byte{0x5D}));
    REQUIRE(sig_bytes[5].match(std::byte{0xA9}));
    REQUIRE(sig_bytes[5].match(std::byte{0x78}));

    REQUIRE(sig_bytes[6].value() == std::byte{0x00});
    REQUIRE(sig_bytes[6].mask() == std::byte{0x00});
    REQUIRE(sig_bytes[6].match(std::byte{0x3F}));
    REQUIRE(sig_bytes[6].match(std::byte{0x86}));
    REQUIRE(sig_bytes[6].match(std::byte{0xCC}));

    REQUIRE(sig_bytes[7].value() == std::byte{0x99});
    REQUIRE(sig_bytes[7].mask() == std::byte{0xFF});
    REQUIRE(sig_bytes[7].match(std::byte{0x99}));
    REQUIRE(!sig_bytes[7].match(std::byte{0x24}));
    REQUIRE(!sig_bytes[7].match(std::byte{0x89}));
}

TEST_CASE("Literal signature correctness", "[signature]")
{
    signature sig_from_vector{{0x7D, 0xDC, {_, 0xB}, {0x9, _}, {_, 0xD}, _, _, 0x24}};
    signature sig_from_literal{"    7d dC ?B  9?  *d  ?? ** 24  "_sig};
    auto sig_from_runtime = signature::parse("    7d dC ?B  9?  *d  ?? ** 24  ");

    REQUIRE(sig_from_vector.size() == 8);
    REQUIRE(sig_from_literal.size() == 8);
    REQUIRE(sig_from_runtime.has_value());
    REQUIRE(sig_from_runtime->size() == 8);
    REQUIRE(sig_from_vector == sig_from_literal);
    REQUIRE(sig_from_vector == sig_from_runtime);

    // 'h' is not a valid hexadecimal digit
    //                                       v
    REQUIRE(!signature::parse("    7d dC ?B  h?  *d  ?? ** 24  ").has_value());
}
