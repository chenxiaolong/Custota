# Copyright (C) 2016-2023  Andrew Gunnerson <andrewgunnerson@gmail.com>
#
# This file is part of Custota, based on DualBootPatcher code.
#
# Custota is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Custota is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Custota.  If not, see <http://www.gnu.org/licenses/>.

add_compile_options(-Werror -Wall -Wextra -Wpedantic -pedantic)

# Enable stack-protector
add_compile_options(-fstack-protector-strong --param ssp-buffer-size=4)

# Enable _FORTIFY_SOURCE for release builds
add_compile_options($<$<CONFIG:RELEASE>:-D_FORTIFY_SOURCE=2>)

# Abort on exceptions to keep binary size small on Android
if(ANDROID)
    add_compile_options(-fno-exceptions -fno-rtti)
endif()

# Disable executable stack
add_compile_options(-Wa,--noexecstack)
add_link_options(-Wl,-z,noexecstack)

# Enable full relro
add_link_options(-Wl,-z,relro -Wl,-z,now)

# Reduce binary size
add_compile_options(-ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections)

# Other useful warnings
add_compile_options(
    -Walloca
    $<$<CXX_COMPILER_ID:Clang>:-Warray-bounds-pointer-arithmetic>
    $<$<CXX_COMPILER_ID:Clang>:-Wassign-enum>
    $<$<COMPILE_LANGUAGE:C>:-Wbad-function-cast>
    -Wcast-align
    -Wcast-qual
    $<$<CXX_COMPILER_ID:Clang>:-Wclass-varargs>
    $<$<CXX_COMPILER_ID:Clang>:-Wcomma>
    $<$<CXX_COMPILER_ID:Clang>:-Wconditional-uninitialized>
    $<$<CXX_COMPILER_ID:Clang>:-Wconsumed>
    -Wconversion
    -Wdate-time
    -Wdouble-promotion
    $<$<CXX_COMPILER_ID:Clang>:-Wduplicate-enum>
    $<$<CXX_COMPILER_ID:Clang>:-Wduplicate-method-arg>
    $<$<CXX_COMPILER_ID:Clang>:-Wduplicate-method-match>
    $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-branches>
    $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-cond>
    $<$<CXX_COMPILER_ID:Clang>:-Wexit-time-destructors>
    -Wfloat-equal
    -Wformat=2
    $<$<CXX_COMPILER_ID:GNU>:-Wformat-overflow=2>
    $<$<CXX_COMPILER_ID:GNU>:-Wformat-truncation=2>
    $<$<CXX_COMPILER_ID:Clang>:-Wheader-hygiene>
    $<$<CXX_COMPILER_ID:Clang>:-Widiomatic-parentheses>
    $<$<CXX_COMPILER_ID:Clang>:-Widiomatic-parentheses>
    -Wimplicit-fallthrough
    $<$<COMPILE_LANG_AND_ID:C,GNU>:-Wjump-misses-init>
    $<$<CXX_COMPILER_ID:GNU>:-Wlogical-op>
    $<$<CXX_COMPILER_ID:Clang>:-Wloop-analysis>
    $<$<CXX_COMPILER_ID:Clang>:-Wmethod-signatures>
    -Wmissing-declarations
    -Wmissing-noreturn
    $<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes>
    $<$<CXX_COMPILER_ID:Clang>:-Wmissing-variable-declarations>
    $<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>
    $<$<CXX_COMPILER_ID:Clang>:-Wover-aligned>
    $<$<COMPILE_LANGUAGE:CXX>:-Woverloaded-virtual>
    $<$<CXX_COMPILER_ID:Clang>:-Wshadow-all>
    -Wsign-conversion
    $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
    $<$<CXX_COMPILER_ID:Clang>:-Wsuper-class-method-mismatch>
    $<$<CXX_COMPILER_ID:Clang>:-Wthread-safety>
    $<$<CXX_COMPILER_ID:GNU>:-Wtrampolines>
    $<$<CXX_COMPILER_ID:Clang>:-Wundefined-func-template>
    $<$<CXX_COMPILER_ID:Clang>:-Wundefined-reinterpret-cast>
    $<$<CXX_COMPILER_ID:Clang>:-Wunreachable-code-aggressive>
    -Wwrite-strings
)

add_library(interface.global.CVersion INTERFACE)
add_library(interface.global.CXXVersion INTERFACE)

target_compile_features(
    interface.global.CVersion
    INTERFACE
    c_std_17
)

target_compile_features(
    interface.global.CXXVersion
    INTERFACE
    cxx_std_17
)

function(link_executable_statically first_target)
    foreach(target "${first_target}" ${ARGN})
        set_property(
            TARGET "${target}"
            APPEND_STRING
            PROPERTY LINK_FLAGS " -static"
        )
        set_target_properties(
            "${target}"
            PROPERTIES
            LINK_SEARCH_START_STATIC ON
        )
    endforeach()
endfunction()
