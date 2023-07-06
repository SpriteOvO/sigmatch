#
# Copyright 2021 SpriteOvO
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required(VERSION 3.14)

project(sigmatch_tests)

include(FetchContent)

##################################################
# Catch2
#

message("Fetching 'Catch2'...")
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY "https://github.com/catchorg/Catch2.git"
    GIT_TAG "5c88067bd339465513af4aec606bd2292f1b594a" # v2.13.6
)
FetchContent_MakeAvailable(Catch2)
message("Fetch 'Catch2' done.")

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/contrib)
include(Catch)

##################################################
# functions
#

function(sigmatch_add_test)
    set(args_options WILL_FAIL)
    set(args_one_value NAME)
    set(args_multi_value)
    cmake_parse_arguments(ARG "${args_options}" "${args_one_value}" "${args_multi_value}" ${ARGN})

    if (NOT ARG_WILL_FAIL)
        add_executable(${ARG_NAME} "main.cpp" "${ARG_NAME}.cpp")
        catch_discover_tests(${ARG_NAME})
    else()
        add_library(${ARG_NAME} STATIC EXCLUDE_FROM_ALL "main.cpp" "${ARG_NAME}.cpp")
        add_test(
            NAME ${ARG_NAME}
            COMMAND ${CMAKE_COMMAND} --build . --target ${ARG_NAME} --config $<CONFIGURATION>
        )
        set_tests_properties(${ARG_NAME} PROPERTIES WILL_FAIL TRUE)
    endif()

    target_link_libraries(${ARG_NAME} PRIVATE sigmatch::sigmatch Catch2::Catch2)
endfunction()

##################################################
# tests
#

sigmatch_add_test(NAME test_details)
sigmatch_add_test(NAME test_literal_sig)
sigmatch_add_test(NAME test_literal_sig_ghidra)
sigmatch_add_test(NAME test_literal_sig_wf_invalid_hex WILL_FAIL TRUE)
sigmatch_add_test(NAME test_literal_sig_wf_ghidra_invalid_bits WILL_FAIL TRUE)
sigmatch_add_test(NAME test_literal_sig_wf_ghidra_invalid_binary WILL_FAIL TRUE)
sigmatch_add_test(NAME test_matcher)
sigmatch_add_test(NAME test_searcher)
sigmatch_add_test(NAME test_target)
