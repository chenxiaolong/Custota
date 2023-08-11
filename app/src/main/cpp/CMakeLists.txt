# SPDX-FileCopyrightText: 2023 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

cmake_minimum_required(VERSION 3.22.1)

project(custota CXX C)

include(cmake/CompilerFlags.cmake)

add_subdirectory(external)
add_subdirectory(custota_selinux)
