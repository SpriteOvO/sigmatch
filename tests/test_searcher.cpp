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

void do_test(
    std::vector<std::function<search_result(const const_byte_span &, const signature &)>> callbacks)
{
    const auto &do_search =
        [&callbacks](const const_byte_span &range, const signature &sig) -> search_result {
        std::optional<search_result> last_result;
        for (const auto &callback : callbacks) {
            search_result result = callback(std::cref(range), std::cref(sig));
            if (last_result.has_value()) {
                REQUIRE(last_result.value() == result);
            }
            last_result = std::move(result);
        }
        return last_result.value();
    };

    {
        std::vector<std::byte> haystack{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05}};

        auto result = do_search(haystack, "02 03 04"_sig);

        REQUIRE(!result.has_error());
        REQUIRE(!result.has_warning());
        REQUIRE(result.matches().size() == 1);
        REQUIRE(result.matches()[0] == &haystack[1]);
    }

    {
        std::vector<std::byte> haystack(0x1000);
        std::vector<std::byte> needle;

        signature full_sig, wildcard_sig;

        // matched, even needle size
        //
        needle = {std::byte{0x13}, std::byte{0x57}, std::byte{0x9B}, std::byte{0xDF}};
        full_sig = "13 57 9B DF"_sig;
        wildcard_sig = "13 5? ?? DF"_sig;

        for (auto iter = haystack.begin(); iter < haystack.end() - needle.size() + 1; ++iter) {
            std::fill(haystack.begin(), haystack.end(), std::byte{0});
            std::copy(needle.begin(), needle.end(), iter);

            auto full_result = do_search(haystack, full_sig);
            auto wildcard_result = do_search(haystack, wildcard_sig);

            REQUIRE(!full_result.has_error());
            REQUIRE(!full_result.has_warning());
            REQUIRE(full_result.matches().size() == 1);
            REQUIRE(full_result.matches()[0] == &*iter);

            REQUIRE(!wildcard_result.has_error());
            REQUIRE(!wildcard_result.has_warning());
            REQUIRE(wildcard_result.matches().size() == 1);
            REQUIRE(wildcard_result.matches()[0] == &*iter);
        }

        // matched, odd needle size
        //
        needle = {
            std::byte{0x13}, std::byte{0x57}, std::byte{0x9B}, std::byte{0xDF}, std::byte{0x2C}};
        full_sig = "13 57 9B DF 2C"_sig;
        wildcard_sig = "13 5? ?? DF 2C"_sig;

        for (auto iter = haystack.begin(); iter < haystack.end() - needle.size() + 1; ++iter) {
            std::fill(haystack.begin(), haystack.end(), std::byte{0});
            std::copy(needle.begin(), needle.end(), iter);

            auto full_result = do_search(haystack, full_sig);
            auto wildcard_result = do_search(haystack, wildcard_sig);

            REQUIRE(!full_result.has_error());
            REQUIRE(!full_result.has_warning());
            REQUIRE(full_result.matches().size() == 1);
            REQUIRE(full_result.matches()[0] == &*iter);

            REQUIRE(!wildcard_result.has_error());
            REQUIRE(!wildcard_result.has_warning());
            REQUIRE(wildcard_result.matches().size() == 1);
            REQUIRE(wildcard_result.matches()[0] == &*iter);
        }

        // matched, even needle size repeat bytes
        //
        needle = {std::byte{0x56}, std::byte{0x56}, std::byte{0x56}, std::byte{0x56}};
        full_sig = "56 56"_sig;
        wildcard_sig = "56 ?6"_sig;

        for (auto iter = haystack.begin(); iter < haystack.end() - needle.size() + 1; ++iter) {
            std::fill(haystack.begin(), haystack.end(), std::byte{0});
            std::copy(needle.begin(), needle.end(), iter);

            auto full_result = do_search(haystack, full_sig);
            auto wildcard_result = do_search(haystack, wildcard_sig);

            REQUIRE(!full_result.has_error());
            REQUIRE(!full_result.has_warning());
            REQUIRE(full_result.matches().size() == 3);
            REQUIRE(full_result.matches()[0] == &*iter);
            REQUIRE(full_result.matches()[1] == &*(iter + 1));
            REQUIRE(full_result.matches()[2] == &*(iter + 2));

            REQUIRE(!wildcard_result.has_error());
            REQUIRE(!wildcard_result.has_warning());
            REQUIRE(wildcard_result.matches().size() == 3);
            REQUIRE(wildcard_result.matches()[0] == &*iter);
            REQUIRE(wildcard_result.matches()[1] == &*(iter + 1));
            REQUIRE(wildcard_result.matches()[2] == &*(iter + 2));
        }

        // matched, odd needle size repeat bytes
        //
        needle = {
            std::byte{0x56}, std::byte{0x56}, std::byte{0x56}, std::byte{0x56}, std::byte{0x56}};
        full_sig = "56 56"_sig;
        wildcard_sig = "56 ?6"_sig;

        for (auto iter = haystack.begin(); iter < haystack.end() - needle.size() + 1; ++iter) {
            std::fill(haystack.begin(), haystack.end(), std::byte{0});
            std::copy(needle.begin(), needle.end(), iter);

            auto full_result = do_search(haystack, full_sig);
            auto wildcard_result = do_search(haystack, wildcard_sig);

            REQUIRE(!full_result.has_error());
            REQUIRE(!full_result.has_warning());
            REQUIRE(full_result.matches().size() == 4);
            REQUIRE(full_result.matches()[0] == &*iter);
            REQUIRE(full_result.matches()[1] == &*(iter + 1));
            REQUIRE(full_result.matches()[2] == &*(iter + 2));
            REQUIRE(full_result.matches()[3] == &*(iter + 3));

            REQUIRE(!wildcard_result.has_error());
            REQUIRE(!wildcard_result.has_warning());
            REQUIRE(wildcard_result.matches().size() == 4);
            REQUIRE(wildcard_result.matches()[0] == &*iter);
            REQUIRE(wildcard_result.matches()[1] == &*(iter + 1));
            REQUIRE(wildcard_result.matches()[2] == &*(iter + 2));
            REQUIRE(wildcard_result.matches()[3] == &*(iter + 3));
        }

        // mismatched, even needle size
        //                                     v mismatched value
        needle = {std::byte{0x13}, std::byte{0x67}, std::byte{0x9B}, std::byte{0xDF}};
        full_sig = "13 57 9B DF"_sig;
        wildcard_sig = "13 5? ?? DF"_sig;

        for (auto iter = haystack.begin(); iter < haystack.end() - needle.size() + 1; ++iter) {
            std::fill(haystack.begin(), haystack.end(), std::byte{0});
            std::copy(needle.begin(), needle.end(), iter);

            auto full_result = do_search(haystack, full_sig);
            auto wildcard_result = do_search(haystack, wildcard_sig);

            REQUIRE(!full_result.has_error());
            REQUIRE(!full_result.has_warning());
            REQUIRE(full_result.matches().empty());

            REQUIRE(!wildcard_result.has_error());
            REQUIRE(!wildcard_result.has_warning());
            REQUIRE(wildcard_result.matches().empty());
        }

        // mismatched, odd needle size
        //                               v mismatched value
        needle = {
            std::byte{0x13}, std::byte{0x67}, std::byte{0x9B}, std::byte{0xDF}, std::byte{0x2C}};
        full_sig = "13 57 9B DF 2C"_sig;
        wildcard_sig = "13 5? ?? DF 2C"_sig;

        for (auto iter = haystack.begin(); iter < haystack.end() - needle.size() + 1; ++iter) {
            std::fill(haystack.begin(), haystack.end(), std::byte{0});
            std::copy(needle.begin(), needle.end(), iter);

            auto full_result = do_search(haystack, full_sig);
            auto wildcard_result = do_search(haystack, wildcard_sig);

            REQUIRE(!full_result.has_error());
            REQUIRE(!full_result.has_warning());
            REQUIRE(full_result.matches().empty());

            REQUIRE(!wildcard_result.has_error());
            REQUIRE(!wildcard_result.has_warning());
            REQUIRE(wildcard_result.matches().empty());
        }

        // matched, fill all
        //
        haystack.resize(0x100000);
        full_sig = "AB AB AB AB"_sig;
        wildcard_sig = "AB AB ?? AB"_sig;

        std::fill(haystack.begin(), haystack.end(), std::byte{0xAB});

        auto full_result = do_search(haystack, full_sig);
        auto wildcard_result = do_search(haystack, wildcard_sig);

        REQUIRE(!full_result.has_error());
        REQUIRE(!full_result.has_warning());
        REQUIRE(full_result.matches().size() == haystack.size() - (full_sig.size() - 1));
        for (size_t i = 0; i < full_result.matches().size(); ++i) {
            const std::byte *matching = full_result.matches()[i];
            REQUIRE(matching == haystack.data() + i);
        }

        REQUIRE(!wildcard_result.has_error());
        REQUIRE(!wildcard_result.has_warning());
        REQUIRE(wildcard_result.matches().size() == haystack.size() - (wildcard_sig.size() - 1));
        for (size_t i = 0; i < wildcard_result.matches().size(); ++i) {
            const std::byte *matching = wildcard_result.matches()[i];
            REQUIRE(matching == haystack.data() + i);
        }

        // matched, fill all
        //
        haystack.resize(0x100123);
        full_sig = "AB AB AB AB"_sig;
        wildcard_sig = "AB AB ?? AB"_sig;

        std::fill(haystack.begin(), haystack.end(), std::byte{0xAB});

        full_result = do_search(haystack, full_sig);
        wildcard_result = do_search(haystack, wildcard_sig);

        REQUIRE(!full_result.has_error());
        REQUIRE(!full_result.has_warning());
        REQUIRE(full_result.matches().size() == haystack.size() - (full_sig.size() - 1));
        for (size_t i = 0; i < full_result.matches().size(); ++i) {
            const std::byte *matching = full_result.matches()[i];
            REQUIRE(matching == haystack.data() + i);
        }

        REQUIRE(!wildcard_result.has_error());
        REQUIRE(!wildcard_result.has_warning());
        REQUIRE(wildcard_result.matches().size() == haystack.size() - (wildcard_sig.size() - 1));
        for (size_t i = 0; i < wildcard_result.matches().size(); ++i) {
            const std::byte *matching = wildcard_result.matches()[i];
            REQUIRE(matching == haystack.data() + i);
        }
    }
}

TEST_CASE("Searchers correctness", "[searcher]")
{
    do_test(
        {[](const const_byte_span &range, const signature &sig) {
             STATIC_REQUIRE(is_copy_move_able_v<blocking_searcher>);
             blocking_searcher sc{std::make_shared<this_process_memory_reader>(), 1};
             search_result result;
             sc.search(range, sig, result);
             return result;
         },
         [](const const_byte_span &range, const signature &sig) {
             blocking_searcher sc{std::make_shared<this_process_memory_reader>(), 0x100};
             search_result result;
             sc.search(range, sig, result);
             return result;
         },
         [](const const_byte_span &range, const signature &sig) {
             STATIC_REQUIRE(is_copy_move_able_v<multi_threaded_searcher>);
             multi_threaded_searcher sc{std::make_shared<this_process_memory_reader>(), 4, 1};
             search_result result;
             sc.search(range, sig, result);
             return result;
         },
         [](const const_byte_span &range, const signature &sig) {
             multi_threaded_searcher sc{std::make_shared<this_process_memory_reader>(), 4, 0x100};
             search_result result;
             sc.search(range, sig, result);
             return result;
         }});
}
