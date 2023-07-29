# Copyright (C) 2023  Andrew Gunnerson
#
# This file is part of Custota.
#
# Custota is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3
# as published by the Free Software Foundation.
#
# Custota is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Custota.  If not, see <http://www.gnu.org/licenses/>.

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
