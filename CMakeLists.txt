cmake_minimum_required(VERSION 3.14)

project(phook VERSION 1.0)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if (NOT CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER /usr/bin/clang)
endif()

set(CMAKE_C_FLAGS_DEBUG "-Wall")
set(CMAKE_C_FLAGS_RELEASE "-Wall -g")

include_directories(${CMAKE_SOURCE_DIR}/src)

file(GLOB phook_src "src/*.c" "src/*/*.c" "src/*/*/*.c")
add_executable(phook ${phook_src})


target_link_libraries(phook elf)
