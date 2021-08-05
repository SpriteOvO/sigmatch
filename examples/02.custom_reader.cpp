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

#include <iostream>

#include <sigmatch/sigmatch.hpp>

using namespace sigmatch_literals;

//
// Implement a custom reader that inherits from `sigmatch::reader`
//

class custom_reader : public sigmatch::reader
{
public:
    //
    // The constructor can have custom arguments. For example, we accept a process id here.
    //

    custom_reader(sigmatch::process_id pid) : _pid{pid} {}

    //
    // If there is an error before reading, the error message needs to be returned in this
    // override function.
    //
    // `[[nodiscard]]` is not required here and in the rest of the code, but using it where
    // appropriate is a good habit in modern C++.
    //

    [[nodiscard]] std::optional<std::string> error() const override
    {
        //
        // If there is an error
        //

        if (_pid == 0) {
            return "The value of argument `pid` cannot be `0`.";
        }

        //
        // If no error
        //

        return std::nullopt;
    }

    //
    // Implement the read function
    //

    [[nodiscard]] bool
    read(const void *address, size_t size, std::vector<std::byte> &result) const override
    {
        //
        // We simply fill `_pid` into `result` here for demonstration purposes, and you can
        // implement the actual read function to suit your needs.
        //

        address; // Eliminate the unused variable warning.
                 // This line is usually not needed in your actual implementation.

        result.resize(size);
        std::memset(result.data(), _pid, size);

        //
        // Returns whether this read was successful.
        //

        return true;
    }

private:
    sigmatch::process_id _pid;
};

int main()
{
    //
    // We assume that `123` here is a correct process id.
    //

    sigmatch::external_process_target target{123, std::make_shared<custom_reader>(123)};

    //
    // We also assume that `0x100000` is a valid address in this external process
    //

    auto ptr = reinterpret_cast<const void *>(0x100000);
    size_t size = 0x1000;

    sigmatch::search_result result = target.in_range({ptr, size}).search("1A 2B ?? ?? 5E 6F"_sig);

    //
    // However, in this example, there can't be any matches, because our reader just fills the bytes
    // with `123` (0x7B).
    //

    for (const std::byte *address : result.matches()) {
        std::cout << "matched: " << address << '\n';
    }
}
