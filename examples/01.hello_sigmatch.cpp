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

//
// Include "sigmatch" header file
//

#include <sigmatch/sigmatch.hpp>

//
// Introduce "sigmatch_literals" namespace.
//
// This is required if you want to use literal signature strings (string suffix `_sig`).
//

using namespace sigmatch_literals;

int main()
{
    //
    // The class `this_process_target` takes the current process as the target.
    //
    // Similar targets are `external_process_target` and `file_target`, etc.
    //

    sigmatch::this_process_target target;

    //
    // Specify the range to be searched later from the target.
    //
    // The argument of `in_module` is a name of a module in the process, on Windows they usually end
    // with ".dll" or ".exe".
    //
    // See the documentation for more ways to specify a range.
    //

    sigmatch::search_context context = target.in_module("**module_name**");

    //
    // Passing the signature to perform a search
    //
    // The literal signature string format has some requirements, see the documentation for details.
    //

    sigmatch::search_result result = context.search("1A ?? 3C ** 5* ?F"_sig);

    //
    // Or you can select a searcher, through `select` function, like this:
    //
    // sigmatch::search_result result =
    //     context.select<sigmatch::multi_threaded_searcher>(4).search("1A ?? 3C ** 5* ?F"_sig);
    //
    // * Argument `4`: Optional argument, means up to 4 threads for search.
    //

    //
    // Get and process matched results
    //

    for (const std::byte *address : result.matches()) {
        std::cout << "matched: " << address << '\n';
    }

    //
    // Here are some optional operations that you can use to check for some errors or warnings.
    // (e.g. target errors, reader errors, read memory warnings, etc)
    //

    std::cout << "has_error: " << std::boolalpha << result.has_error() << '\n';
    std::cout << "has_warning: " << std::boolalpha << result.has_warning() << '\n';

    for (const std::string &error_message : result.error_messages()) {
        std::cout << "error_message: " << error_message << '\n';
    }
    for (const std::string &warning_message : result.warning_messages()) {
        std::cout << "warning_message: " << warning_message << '\n';
    }
}
