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

TEST_CASE("Literal signature WF", "[signature]")
{
    // 'G' is not a valid hexadecimal digit, we expect this to cause a compile error
    //                       v
    auto sig_bytes = "1A B2 3G D4"_sig;
}
