cmake_minimum_required(VERSION 3.16)
project(aegis_ipc_bridge VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ====== Platform Detection ======
if(WIN32)
    message(STATUS "[AEGIS Bridge] Building for Windows")
    add_definitions(-D_AEGIS_WINDOWS)
else()
    message(STATUS "[AEGIS Bridge] Building for Linux")
    add_definitions(-D_AEGIS_LINUX)
endif()

# ====== Compiler Flags ======
# MSVC: /EHsc = C++ exceptions + extern"C" never throws (needed by UCRT)
# GCC/Clang: -fno-exceptions not used — UCRT stdio requires exception support
if(MSVC)
    add_compile_options(/EHsc /W4)
    # Prevent winsock.h / winsock2.h conflict
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOGDI -DNOMINMAX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ====== Bridge Shared Library (DLL / .so) ======
add_library(aegis_ipc SHARED
    bridge/aegis_ipc.cpp
    bridge/aegis_packet_parser.cpp
)

target_include_directories(aegis_ipc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ====== Bridge Standalone Executable ======
add_executable(aegis_bridge
    bridge/aegis_bridge_main.cpp
    bridge/aegis_ipc.cpp
    bridge/aegis_packet_parser.cpp
)

target_include_directories(aegis_bridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ====== Bridge Test Executable ======
add_executable(aegis_bridge_test
    bridge/aegis_bridge_test.cpp
    bridge/aegis_ipc.cpp
    bridge/aegis_packet_parser.cpp
)

target_include_directories(aegis_bridge_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ====== Install ======
install(TARGETS aegis_ipc aegis_bridge aegis_bridge_test
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
