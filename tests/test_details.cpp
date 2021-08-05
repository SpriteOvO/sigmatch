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

TEST_CASE("Text to_lower", "[details][text]")
{
    REQUIRE(details::text::to_lower("1A5%vDe$F69") == "1a5%vde$f69");
    REQUIRE(details::text::to_lower(L"23fGh(53DSf") == L"23fgh(53dsf");
}
TEST_CASE("Text to_upper", "[details][text]")
{
    REQUIRE(details::text::to_upper("4sd3fSg@F6f") == "4SD3FSG@F6F");
    REQUIRE(details::text::to_upper(L"34ds3$4sd5f") == L"34DS3$4SD5F");
}

#if defined SIGMATCH_PLATFORM_WINDOWS

TEST_CASE("Text convert utf8_to_wide_char", "[details][text]")
{
    REQUIRE(details::text::convert::utf8_to_wide_char("abcd12 34!@#$") == L"abcd12 34!@#$");
    REQUIRE(
        details::text::convert::utf8_to_wide_char(u8"abcd12 34!@#$测试テスト시험") ==
        L"abcd12 34!@#$测试テスト시험");
}

TEST_CASE("Text convert wide_char_to_utf8", "[details][text]")
{
    REQUIRE(details::text::convert::wide_char_to_utf8(L"abcd12 34!@#$") == "abcd12 34!@#$");
    REQUIRE(
        details::text::convert::wide_char_to_utf8<std::u8string>(L"abcd12 34!@#$测试テスト시험") ==
        u8"abcd12 34!@#$测试テスト시험");
}

#endif
