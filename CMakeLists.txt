# Copyright (C) 2019 Geon Technologies, LLC
#
# This file is part of wireshark-vrtgen.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

cmake_minimum_required(VERSION 3.13)
project(wireshark-vrtgen VERSION 0.2.0 LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(WIRESHARK REQUIRED IMPORTED_TARGET "wireshark >= 1.10")
set(PLUGINDIR "${WIRESHARK_LIBDIR}/wireshark/plugins/${WIRESHARK_VERSION}")
message(STATUS "  Plugin directory ${PLUGINDIR}")

find_package(Python3 REQUIRED)

# Ensure that the base vrtgen Python library is available
execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import vrtgen"
    OUTPUT_QUIET
    ERROR_QUIET
    RESULT_VARIABLE import_vrtgen_error_code
)
if(NOT import_vrtgen_error_code EQUAL 0)
    message(FATAL_ERROR "vrtgen Python package not found")
else()
    message(STATUS "Found vrtgen Python package")
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/moduleinfo.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/moduleinfo.h
)

set(generated_header_files
    ${CMAKE_CURRENT_BINARY_DIR}/enums.h
    ${CMAKE_CURRENT_BINARY_DIR}/cif0.h
    ${CMAKE_CURRENT_BINARY_DIR}/cif1.h
    ${CMAKE_CURRENT_BINARY_DIR}/prologue.h
)
# List template files used to generate headers, used to trigger a re-generate
# step if they are modified
set(template_files
    ${CMAKE_CURRENT_SOURCE_DIR}/templates/cif.h
    ${CMAKE_CURRENT_SOURCE_DIR}/templates/dissector.h
    ${CMAKE_CURRENT_SOURCE_DIR}/templates/enums.h
    ${CMAKE_CURRENT_SOURCE_DIR}/templates/prologue.h
)

add_custom_command(
    OUTPUT
        ${generated_header_files}
    COMMAND
        ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/generate.py
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/generate.py
        ${CMAKE_CURRENT_SOURCE_DIR}/strings.yml
        ${template_files}
)

# Define an intermediate target to ensure that header generation only occurs
# once, as part of the vrtgen target
add_custom_target(generate-headers DEPENDS ${generated_header_files})

# Compile everything with most warnings
add_compile_options(
  "-Wall" "-Wpedantic" "-Wextra"
)

add_library(v49d2 MODULE)
# Make module name "v49d2.so" instead of "libv49d2.so"
set_target_properties(v49d2 PROPERTIES PREFIX "")

target_link_libraries(v49d2 PRIVATE PkgConfig::WIRESHARK)
target_include_directories(v49d2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_sources(v49d2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/packet-v49d2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin.c
    ${generated_header_files}
)

# Install to the Wireshark plugin directory
install(TARGETS v49d2
    LIBRARY
        DESTINATION ${PLUGINDIR}
        COMPONENT Libraries
)

# Packaging options
set(CPACK_PACKAGE_NAME wireshark-v49d2)
set(CPACK_PACKAGE_VENDOR "Geon Technologies, LLC")
set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
set(CPACK_RPM_PACKAGE_REQUIRES "wireshark")
set(CPACK_RPM_BUILDREQUIRES "wireshark-devel")
set(CPACK_RPM_PACKAGE_SUMMARY "Wireshark VITA 49.2 dissector plugin using vrtgen to generate packet unpacking routines.")
include(CPack)
