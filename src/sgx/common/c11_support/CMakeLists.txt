# Copyright 2018 Intel Corporation
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
# ------------------------------------------------------------------------------

CMAKE_MINIMUM_REQUIRED(VERSION 3.2 FATAL_ERROR)
PROJECT(safe_functions CXX)

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# Source Code
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SET(PLATFORM_DIR_NAME linux)

FILE(GLOB PROJECT_HEADERS ${PLATFORM_DIR_NAME}/*.h)
FILE(GLOB PROJECT_SOURCES ${PLATFORM_DIR_NAME}/*.cpp)
SOURCE_GROUP("Source" FILES ${PROJECT_HEADERS} ${PROJECT_SOURCES})

INCLUDE_DIRECTORIES(.)

# These compiler and linker flags for g++/gcc were derived from the make
# files provided with the SGX sample apps
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-attributes")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# Compile targets
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

ADD_LIBRARY(${PROJECT_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${EXECUTABLE_OUTPUT_PATH}"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:${PROJECT_NAME}>" "${EXECUTABLE_OUTPUT_PATH}"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_LINKER_FILE:${PROJECT_NAME}>" "${LIBRARY_OUTPUT_PATH}"
)
