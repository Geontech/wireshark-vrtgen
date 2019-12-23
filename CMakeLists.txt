cmake_minimum_required(VERSION 3.13)
project(wireshark-vrtgen VERSION 0.1.0 LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(WIRESHARK REQUIRED IMPORTED_TARGET "wireshark >= 1.10")
set(PLUGINDIR "${WIRESHARK_LIBDIR}/wireshark/plugins/${WIRESHARK_VERSION}")
message(STATUS "  Plugin directory ${PLUGINDIR}")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/moduleinfo.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/moduleinfo.h
)

add_library(v49d2 MODULE)
# Make module name "v49d2.so" instead of "libv49d2.so"
set_target_properties(v49d2 PROPERTIES PREFIX "")

target_link_libraries(v49d2 PRIVATE PkgConfig::WIRESHARK)
target_include_directories(v49d2 PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_sources(v49d2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/packet-v49d2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/plugin.c
)

# Install to the Wireshark plugin directory
install(TARGETS v49d2
    LIBRARY
        DESTINATION ${PLUGINDIR}
        COMPONENT Libraries
)
