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

cmake_minimum_required(VERSION 3.0)

project(sigmatch_examples)

function(sigmatch_add_example name)
    add_executable(${name} "${name}.cpp")
    target_link_libraries(${name} PRIVATE sigmatch::sigmatch)
endfunction()

sigmatch_add_example("01.hello_sigmatch")
sigmatch_add_example("02.custom_reader")
sigmatch_add_example("03.custom_target")
