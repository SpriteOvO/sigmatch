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

#include <catch2/catch.hpp>

#include <sigmatch/sigmatch.hpp>

namespace utils {

class defer
{
public:
    explicit inline defer(std::function<void()> callback) noexcept : _callback{std::move(callback)}
    {
    }

    inline ~defer()
    {
        if (!_canceled && _callback) {
            _callback();
        }
    }

    inline void cancel() noexcept
    {
        _canceled = true;
    }

private:
    std::function<void()> _callback;
    std::atomic<bool> _canceled{false};
};

// clang-format off
#define DEFER_NAMED(var, callback) utils::defer var{callback}
// clang-format on
#define DEFER(callback) DEFER_NAMED(____defer_variable_##__LINE__, callback)

} // namespace utils

// clang-format off
template <class T>
constexpr inline bool is_copy_move_able_v =
    std::is_copy_constructible_v<T> && std::is_copy_assignable_v<T> &&
    std::is_move_constructible_v<T> && std::is_move_assignable_v<T>;
// clang-format on
