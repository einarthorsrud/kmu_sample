#
# Copyright (c) 2020 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(NONE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

FILE(GLOB app_src src/*.c)

target_sources(app PRIVATE ${app_src})
target_include_directories(app PRIVATE src)
