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
# GCC/Clang: -fno-exceptions not used â€” UCRT stdio requires exception support
if(MSVC)
    add_compile_options(/EHsc /W4)
    # Prevent winsock.h / winsock2.h conflict
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOGDI -DNOMINMAX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ====== Output to dist/ (MUST be set BEFORE add_library/add_executable) ======
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../dist)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../dist)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../dist)

# Also set per-config output (MSVC uses Release/ subdirectory by default)
foreach(CONFIG_TYPE DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    string(TOUPPER ${CONFIG_TYPE} CONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_SOURCE_DIR}/../dist)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_SOURCE_DIR}/../dist)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_SOURCE_DIR}/../dist)
endforeach()

# ====== Bridge Shared Library (DLL / .so) ======
add_library(aegis_ipc SHARED
    aegis_ipc.cpp
    aegis_packet_parser.cpp
)

# MinGW: remove lib prefix so output is aegis_ipc.dll not libaegis_ipc.dll
set_target_properties(aegis_ipc PROPERTIES PREFIX "")

target_include_directories(aegis_ipc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Force output to dist/ for MSVC (DLLs go to RUNTIME on Windows)
set_target_properties(aegis_ipc PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../dist"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../dist"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../dist"
)
foreach(CONFIG_TYPE DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    string(TOUPPER ${CONFIG_TYPE} CONFIG_UPPER)
    set_target_properties(aegis_ipc PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${CMAKE_SOURCE_DIR}/../dist"
        LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${CMAKE_SOURCE_DIR}/../dist"
        ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} "${CMAKE_SOURCE_DIR}/../dist"
    )
endforeach()

# ====== Bridge Standalone Executable ======
add_executable(aegis_bridge
    aegis_bridge_main.cpp
    aegis_ipc.cpp
    aegis_packet_parser.cpp
)

target_include_directories(aegis_bridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
set_target_properties(aegis_bridge PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../dist"
)

# ====== Bridge Test Executable ======
add_executable(aegis_bridge_test
    aegis_bridge_test.cpp
    aegis_ipc.cpp
    aegis_packet_parser.cpp
)

target_include_directories(aegis_bridge_test PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ====== Install ======
install(TARGETS aegis_ipc aegis_bridge aegis_bridge_test
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
