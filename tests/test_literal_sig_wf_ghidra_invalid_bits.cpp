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

#define SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT

#include "includes.hpp"

using namespace sigmatch;
using namespace sigmatch_literals;

TEST_CASE("Literal signature WF ghidra invalid bits", "[signature]")
{
    // 7 bits wildcard
    //                      vvvvvvvvv
    auto sig_bytes = "1A B2 [.......] D4"_sig;
}
