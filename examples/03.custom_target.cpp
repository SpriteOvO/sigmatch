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
#include <cassert>

#include <sigmatch/sigmatch.hpp>

using namespace sigmatch_literals;

//
// We assume that this is a network packet and we need to match / search signatures from it
//

struct network_packet
{
    uint32_t magic{0xABCD};
    unsigned char header[0x1000];
    unsigned char body[0x5000];
};

//
// Implement a custom target that inherits from `sigmatch::access_memory_target` or
// `sigmatch::target`
//
// `sigmatch::access_memory_target` provides more detail related range functions than
// `sigmatch::target`
//

class custom_target : public sigmatch::access_memory_target
{
public:
    //
    // The constructor can have custom arguments. For example, we accept a const reference to
    // `network_packet` here.
    //

    custom_target(const network_packet &packet)
        : sigmatch::access_memory_target{std::make_shared<sigmatch::this_process_memory_reader>()},
          _packet{packet}
    {
    }

    //
    // You can optionally override the `error()` function if an error may occur in your target. By
    // default, it calls the `error()` function of the reader directly and returns it.
    //

    [[nodiscard]] std::optional<std::string> error() const override
    {
        //
        // If there is an error in the target
        //

        if (_packet.magic != 0xABCD) {
            return "The packet data is invalid.";
        }

        //
        // If no error
        //

        return sigmatch::target::error();
    }

    //
    // Implement range functions
    //

    [[nodiscard]] sigmatch::search_context in_whole() const
    {
        auto opt_error = opt_target_error();
        if (opt_error.has_value()) {
            return opt_error.value();
        }

        return in_range({&_packet, sizeof(network_packet)});
    }

    [[nodiscard]] sigmatch::search_context in_header() const
    {
        auto opt_error = opt_target_error();
        if (opt_error.has_value()) {
            return opt_error.value();
        }

        return in_range({&_packet.header, sizeof(network_packet::header)});
    }

    [[nodiscard]] sigmatch::search_context in_body() const
    {
        auto opt_error = opt_target_error();
        if (opt_error.has_value()) {
            return opt_error.value();
        }

        return in_range({&_packet.body, sizeof(network_packet::body)});
    }

private:
    const network_packet &_packet;

    std::optional<sigmatch::search_context> opt_target_error() const
    {
        auto target_error = error();
        if (target_error.has_value()) {
            return sigmatch::search_context::make_error(std::move(target_error.value()));
        }
        return std::nullopt;
    }
};

int main()
{
    //
    // We assume that the packet is coming from the network, whether it is sent to us from the
    // server or intercepted by us.
    //

    auto packet_ptr = std::make_unique<network_packet>();
    network_packet &packet = *packet_ptr;

    std::memset(&packet.header, 0xAB, sizeof(network_packet::header));
    std::memset(&packet.body, 0xCD, sizeof(network_packet::body));

    //
    // Now we need to do some matching / searching
    //

    custom_target target{packet};

    sigmatch::search_result result;
    sigmatch::signature sig;

    sig = "AB AB AB AB"_sig;
    result = target.in_header().search(sig);
    std::cout << "[header] matches count: " << result.matches().size() << '\n';
    assert(!result.has_error());
    assert(!result.has_warning());
    assert(result.matches().size() == sizeof(network_packet::header) - (sig.size() - 1));

    sig = "CD CD CD CD"_sig;
    result = target.in_body().search(sig);
    std::cout << "[body] matches count: " << result.matches().size() << '\n';
    assert(!result.has_error());
    assert(!result.has_warning());
    assert(result.matches().size() == sizeof(network_packet::body) - (sig.size() - 1));

    result = target.in_whole().search("AB AB CD CD"_sig);
    std::cout << "[whole] matches count: " << result.matches().size() << '\n';
    assert(!result.has_error());
    assert(!result.has_warning());
    assert(result.matches().size() == 1);
}
