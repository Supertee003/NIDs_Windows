# I01 - CMakeLists for native C components (WFP kernel callout, ETW helpers, FIM)
cmake_minimum_required(VERSION 3.20)
project(aegis_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
add_compile_options(
    /W4 /WX- /permissive- /utf-8
    /D_CRT_SECURE_NO_WARNINGS
    /DWIN32_LEAN_AND_MEAN
    /DNOMINMAX
    /DUNICODE /D_UNICODE
)

# ----- WFP User-mode Helper Library (links to aegis_nids.exe) -----
add_library(aegis_wfp_user SHARED
    src/windows/aegis_wfp.c
    src/windows/wfp_ioctl.c
)
target_link_libraries(aegis_wfp_user PRIVATE
    fwpuclnt
    rpcrt4
    kernel32
    advapi32
)
target_include_directories(aegis_wfp_user PRIVATE
    src/windows
    ${CMAKE_SOURCE_DIR}
)

# ----- ETW Native Helper -----
add_library(aegis_etw_helper SHARED
    src/windows/etw_native.c
)
target_link_libraries(aegis_etw_helper PRIVATE
    tdh
    advapi32
    kernel32
)

# ----- FIM Native Helper -----
add_library(aegis_fim_helper SHARED
    src/windows/fim_native.c
)
target_link_libraries(aegis_fim_helper PRIVATE
    kernel32
    advapi32
)

# Install rules
install(TARGETS aegis_wfp_user aegis_etw_helper aegis_fim_helper
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Optionally build kernel-mode driver (requires WDK)
option(BUILD_KERNEL_DRIVER "Build the WFP kernel-mode callout driver" OFF)
if(BUILD_KERNEL_DRIVER)
    # User must have WDK installed and EWDK environment
    add_subdirectory(kernel/wfp_callout)
endif()
