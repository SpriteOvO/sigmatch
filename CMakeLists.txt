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

cmake_minimum_required(VERSION 3.13)

if (DEFINED PROJECT_NAME)
    set(SIGMATCH_STANDALONE OFF)
else()
    set(SIGMATCH_STANDALONE ON)
endif()

option(SIGMATCH_BUILD_TESTS   "Build tests" ON)

include(CMakeDependentOption)
cmake_dependent_option(SIGMATCH_DEV_MODE         "Development mode" ON  "SIGMATCH_STANDALONE" OFF)
cmake_dependent_option(SIGMATCH_GENERATE_DOCS    "Generate docs"    OFF "SIGMATCH_STANDALONE" OFF)
cmake_dependent_option(SIGMATCH_BUILD_EXAMPLES   "Build examples"   ON  "SIGMATCH_STANDALONE" OFF)
cmake_dependent_option(SIGMATCH_BUILD_BENCHMARKS "Build benchmarks" ON  "SIGMATCH_STANDALONE" OFF)

if (SIGMATCH_DEV_MODE)
    if (MSVC)
        add_compile_options(
            "/W4"                   # Warning level = Level4
            "/WX"                   # Treat warnings as errors = Yes
            "/MP"                   # Multi-processor compilation = Yes
            "/Zc:preprocessor"      # Enable MSVC preprocessor conformance
        )
    endif()
endif()

project(sigmatch LANGUAGES CXX VERSION 0.1.0)

add_library(sigmatch INTERFACE)
add_library(sigmatch::sigmatch ALIAS sigmatch)

target_include_directories(
    sigmatch INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_compile_features(sigmatch INTERFACE cxx_std_20)

if (SIGMATCH_BUILD_TESTS)
    include(CTest)
    add_subdirectory(tests)
endif()

if (SIGMATCH_GENERATE_DOCS)
    find_package(Doxygen)
    if (NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen not found.")
    endif()
    message("Doxygen version: ${DOXYGEN_VERSION}")

    set(DOXYGEN_PREDEFINED "SIGMATCH_DOXYGEN")
    set(DOXYGEN_SORT_MEMBER_DOCS "NO")

    doxygen_add_docs(
        sigmatch_docs
        "include/sigmatch/sigmatch.hpp"
        "README.md"
        ALL
        COMMENT "Documentations generating..."
    )
endif()

if (SIGMATCH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if (SIGMATCH_BUILD_BENCHMARKS)
    # TODO
endif()
