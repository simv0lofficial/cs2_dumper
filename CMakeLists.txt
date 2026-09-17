cmake_minimum_required(VERSION 3.20)
project(cs2-dumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(cs2-dumper
    src/main.cpp
    src/process.cpp
    src/pe.cpp
    src/analysis.cpp
    src/output.cpp
)

target_include_directories(cs2-dumper PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/thirdparty
)

if(MSVC)
    target_compile_options(cs2-dumper PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8)
    target_compile_options(cs2-dumper PRIVATE $<$<CONFIG:Release>:/O2>)
endif()

target_compile_definitions(cs2-dumper PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)
