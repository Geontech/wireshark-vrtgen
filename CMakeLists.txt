cmake_minimum_required(VERSION 3.13)
project(wireshark-vrtgen VERSION 0.1.0 LANGUAGES C)

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
