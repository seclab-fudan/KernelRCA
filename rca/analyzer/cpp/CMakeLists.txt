cmake_minimum_required(VERSION 3.25)
set(CMAKE_CXX_COMPILER "/usr/bin/g++-11")

project(Analyzer)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

# capstone
include(FindPkgConfig)
pkg_check_modules(CAPSTONE REQUIRED capstone)
# protobuf 支持
find_package(Protobuf REQUIRED)

# JSON
include(FetchContent)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)

# libdwarf
add_subdirectory(libdwarf-0.4.1)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/vex/pub)
include_directories(${CMAKE_SOURCE_DIR}/vex/priv)
include_directories(${CMAKE_SOURCE_DIR}/elfio-3.12)
include_directories(${CMAKE_SOURCE_DIR}/include/spdlog)
include_directories(${CMAKE_SOURCE_DIR}/libdwarf-0.4.1/src/lib/libdwarf)
include_directories(${Protobuf_INCLUDE_DIRS})
link_directories(${CMAKE_SOURCE_DIR}/vex)
link_directories(${PROJECT_BINARY_DIR}/libdwarf-0.4.1/src/lib/libdwarf)

aux_source_directory(src SRC)
protobuf_generate_cpp(TRACE_PROTO_SRCS TRACE_PROTO_HDRS src/trace.proto)
protobuf_generate_cpp(RAWTRACE_PROTO_SRCS RAWTRACE_PROTO_HDRS src/RawTrace.proto)

link_directories(${CMAKE_CURRENT_BINARY_DIR}/install/lib)

################ TreeBuilder ################
set(TreeBuilderSRC src/TreeBuilder.cc src/IRTranslator.cc src/TaintEngine.cc src/SimuVex.cc src/SimuFunc.cc src/machine.cc)
set(RootCauseSRC src/TypeInfo.cc src/RootCauseAnalyzer.cc)
# set(TreeBuilderSRC src/TreeBuilder.cc src/TaintEngine.cc)

add_executable(TreeBuilder ${TreeBuilderSRC} ${RootCauseSRC} ${TRACE_PROTO_SRCS} ${TRACE_PROTO_HDRS})

add_custom_command(
    TARGET TreeBuilder PRE_BUILD
    COMMAND MULTIARCH=1 make -f Makefile-gcc -C ${CMAKE_SOURCE_DIR}/vex
    VERBATIM)

ExternalProject_Add(jemalloc
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/jemalloc
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/jemalloc/configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/install
    BUILD_COMMAND make -j16 && make install
)

ExternalProject_Add_Step(jemalloc autogen
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/jemalloc
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/jemalloc/autogen.sh
    DEPENDERS configure
)

target_link_libraries(TreeBuilder PUBLIC ${CAPSTONE_LIBRARIES} ${Protobuf_LIBRARIES} libvex.a PRIVATE dwarf-static z nlohmann_json::nlohmann_json libjemalloc.a pthread dl)
add_dependencies(TreeBuilder jemalloc)
# target_compile_options(TreeBuilder PRIVATE -O2)
# target_compile_options(TreeBuilder PRIVATE -fsanitize=address)

################ TraceSlicer ################
set (TraceSlicerSRC src/TraceSlicer.cc)

add_executable(TraceSlicer ${TraceSlicerSRC} ${TRACE_PROTO_SRCS} ${TRACE_PROTO_HDRS} ${RAWTRACE_PROTO_SRCS} ${RAWTRACE_PROTO_HDRS})

target_link_libraries(TraceSlicer PUBLIC ${CAPSTONE_LIBRARIES} ${Protobuf_LIBRARIES} PRIVATE nlohmann_json::nlohmann_json)
target_compile_options(TraceSlicer PRIVATE -O2)
# target_compile_options(TraceSlicer PRIVATE -fsanitize=address)
