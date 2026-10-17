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
    # Delegate to the sanctioned WDK build script instead of invoking cl.exe
    # directly. scripts/wdk_build_production.ps1 is the single authoritative
    # driver build (MSVC/WDK discovery, kernel-mode flags, link libs) and it
    # emits build/x64/wfp/aegis_wfp.sys. It needs no elevation; signing and
    # deployment stay separate, explicit steps (wfp_sign.ps1 / wfp_service.ps1).
    find_program(AEGIS_POWERSHELL_EXE NAMES powershell pwsh)
    if(NOT AEGIS_POWERSHELL_EXE)
        message(FATAL_ERROR "BUILD_KERNEL_DRIVER=ON requires PowerShell to run scripts/wdk_build_production.ps1")
    endif()
    add_custom_target(aegis_wfp_kernel ALL
        COMMAND ${AEGIS_POWERSHELL_EXE} -ExecutionPolicy Bypass -File
                "${CMAKE_CURRENT_SOURCE_DIR}/scripts/wdk_build_production.ps1"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Building WFP kernel driver via scripts/wdk_build_production.ps1"
        VERBATIM)
endif()
