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

// "This program cannot be run in DOS mode"
auto pe_dos_header_words_sig =
    "54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65"_sig;

search_result do_search(const search_context &ctx, const signature &sig)
{
    STATIC_REQUIRE(is_copy_move_able_v<search_context>);

    const auto &run = [](std::vector<std::function<search_result()>> callbacks) -> search_result {
        std::optional<search_result> last_result;
        for (const auto &callback : callbacks) {
            search_result result = callback();
            if (last_result.has_value()) {
                REQUIRE(last_result.value() == result);
            }
            last_result = std::move(result);
        }
        return last_result.value();
    };

    return run(
        {[&] { return ctx.select<blocking_searcher>().search(sig); },
         [&] { return ctx.select<blocking_searcher>(0x100).search(sig); },
         [&] { return ctx.select<blocking_searcher>(0x123).search(sig); },
         [&] { return ctx.select<multi_threaded_searcher>(3).search(sig); },
         [&] { return ctx.select<multi_threaded_searcher>(3, 0x100).search(sig); },
         [&] { return ctx.select<multi_threaded_searcher>(3, 0x123).search(sig); },
         [&] { return ctx.select<multi_threaded_searcher>(4).search(sig); },
         [&] { return ctx.select<multi_threaded_searcher>(4, 0x100).search(sig); },
         [&] { return ctx.select<multi_threaded_searcher>(4, 0x123).search(sig); }});
}

TEST_CASE("This process target", "[target]")
{
    STATIC_REQUIRE(is_copy_move_able_v<this_process_target>);

#if defined SIGMATCH_PLATFORM_WINDOWS
    this_process_target target;

    auto result = do_search(target.in_module("test_target.exe"), pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().size() == 1);

    result =
        do_search(target.in_module("test_target.exe", mem_prot::read), pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().size() == 1);

    result = do_search(
        target.in_module("test_target.exe", mem_prot::read | mem_prot::write),
        pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().empty());

    result = do_search(
        target.in_module("test_target.exe", mem_prot::read | mem_prot::execute),
        pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().empty());
#else
    #error "Unimplemented."
#endif
}

TEST_CASE("External process target", "[target]")
{
    STATIC_REQUIRE(is_copy_move_able_v<external_process_target>);

    struct process_launch_info
    {
        process_id pid{0};
#if defined SIGMATCH_PLATFORM_WINDOWS
        HANDLE handle{nullptr};
#endif
    };

    const auto &launch_process =
        [](const std::string_view &name) -> std::optional<process_launch_info> {

#if defined SIGMATCH_PLATFORM_WINDOWS
        STARTUPINFOA startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_MINIMIZE;

        PROCESS_INFORMATION processInfo{};

        bool isCreateSuccess = CreateProcessA(
            name.data(), nullptr, nullptr, nullptr, false, 0, nullptr, nullptr, &startupInfo,
            &processInfo);
        if (!isCreateSuccess) {
            return std::nullopt;
        }

        std::this_thread::sleep_for(1s);

        CloseHandle(processInfo.hThread);

        return process_launch_info{.pid = processInfo.dwProcessId, .handle = processInfo.hProcess};
#else
    #error "Unimplemented."
#endif
    };

    const auto &kill_process = [](const process_launch_info &info) {
#if defined SIGMATCH_PLATFORM_WINDOWS
        if (info.handle != nullptr) {
            TerminateProcess(info.handle, 0);
            CloseHandle(info.handle);
        }
#else
    #error "Unimplemented."
#endif
    };

#if defined SIGMATCH_PLATFORM_WINDOWS
    auto info = launch_process("C:\\Windows\\System32\\notepad.exe");
    REQUIRE(info.has_value());

    DEFER([&] { kill_process(info.value()); });

    external_process_target target{info->pid};

    auto result = do_search(target.in_module("notepad.exe"), pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().size() == 1);

    result = do_search(target.in_module("notepad.exe", mem_prot::read), pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().size() == 1);

    result = do_search(
        target.in_module("notepad.exe", mem_prot::read | mem_prot::write), pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().empty());

    result = do_search(
        target.in_module("notepad.exe", mem_prot::read | mem_prot::execute),
        pe_dos_header_words_sig);
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().empty());
#else
    #error "Unimplemented."
#endif
}

TEST_CASE("File target", "[target]")
{
    STATIC_REQUIRE(is_copy_move_able_v<file_target>);

    constexpr auto file_name = "test_target_file_target_haystack.txt";

    {
        std::ofstream file{file_name};
        file << std::string(0x12345, 'A');
        file << "BCD";
        file << std::string(0x56789, 'E');
    }

    DEFER([]() { std::filesystem::remove(file_name); });

    file_target target{file_name};

    auto result = do_search(target.in_whole(), "42 43 44"_sig); // "BCD" == { 0x42, 0x43, 0x44 }
    REQUIRE(!result.has_error());
    REQUIRE(!result.has_warning());
    REQUIRE(result.matches().size() == 1);
    REQUIRE(result.matches()[0] == reinterpret_cast<const std::byte *>(0x12345));
}
