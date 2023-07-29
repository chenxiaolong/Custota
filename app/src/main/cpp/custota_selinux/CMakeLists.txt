# Copyright (C) 2023  Andrew Gunnerson
#
# SPDX-License-Identifier: GPL-3.0-only

add_executable(
    custota_selinux
    src/main.cpp
)

target_include_directories(
    custota_selinux
    PRIVATE
    include
)

target_compile_options(
    custota_selinux
    PRIVATE
    $<$<CXX_COMPILER_ID:Clang>:-Wno-keyword-macro>
)

set_target_properties(
    custota_selinux
    PROPERTIES
    POSITION_INDEPENDENT_CODE TRUE
)

target_link_libraries(
    custota_selinux
    PRIVATE
    interface.global.CXXVersion
    sepol
)

link_executable_statically(custota_selinux)

# Make the file look like a library or else it won't be added to the APK.
if(ANDROID)
    set_target_properties(
        custota_selinux
        PROPERTIES
        OUTPUT_NAME libcustota_selinux.so
    )
endif()
