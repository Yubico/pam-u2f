# Copyright (c) 2024 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the COPYING file.
# SPDX-License-Identifier: BSD-2-Clause
cmake_minimum_required(VERSION 3.12)

project(pam_u2f VERSION 1.3.1 LANGUAGES C)

# Set C macros
add_compile_definitions(PACKAGE_BUGREPORT="https://github.com/Yubico/pam-u2f/issues")
add_compile_definitions(PACKAGE_VERSION="${CMAKE_PROJECT_VERSION}")

include(GNUInstallDirs)
include(FindPkgConfig)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)

option(BUILD_TESTS "Build the tests" ON)
option(BUILD_MANPAGES "Build man pages" ON)

add_compile_options(-Wall)
add_compile_options(-Wbad-function-cast)
add_compile_options(-Wcast-qual)
add_compile_options(-Wconversion)
add_compile_options(-Wextra)
add_compile_options(-Wformat=2)
add_compile_options(-Wimplicit-fallthrough)
add_compile_options(-Wmissing-declarations)
add_compile_options(-Wmissing-prototypes)
add_compile_options(-Wmissing-prototypes)
add_compile_options(-Wnull-dereference)
add_compile_options(-Wshadow)
add_compile_options(-Wstrict-prototypes)
add_compile_options(-Wwrite-strings)
add_compile_options(-pedantic-errors)
add_compile_options(-pedantic)

pkg_search_module(FIDO2 REQUIRED libfido2)
pkg_search_module(CRYPTO REQUIRED libcrypto)
pkg_search_module(PAM REQUIRED pam)

include_directories(.)
include_directories(${FIDO2_INCLUDE_DIRS})
include_directories(${CRYPTO_INCLUDE_DIRS})
include_directories(${PAM_INCLUDE_DIRS})

link_directories(${FIDO2_LIBRARY_DIRS})
link_directories(${CRYPTO_LIBRARY_DIRS})
link_directories(${PAM_LIBRARY_DIRS})


set(CMAKE_REQUIRED_LIBRARIES
        ${FIDO2_LIBRARIES}
        ${CRYPTO_LIBRARIES}
        ${PAM_LIBRARIES}
)
check_include_file(unistd.h HAVE_UNISTD_H)
check_symbol_exists(pam_modutil_drop_priv "/usr/include/security/pam_modutil.h" HAVE_PAM_MODUTIL_DROP_PRIV)
check_symbol_exists(openpam_borrow_cred  "security/openpam.h" HAVE_OPENPAM_BORROW_CRED)

set(CHECK_VARIABLES
        HAVE_UNISTD_H
        HAVE_PAM_MODUTIL_DROP_PRIV
        HAVE_OPENPAM_BORROW_CRED
)

foreach(v ${CHECK_VARIABLES})
    if (${v})
        add_compile_definitions(${v})
    endif()
endforeach()


add_subdirectory(pamu2fcfg)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(BUILD_MANPAGES)
    add_subdirectory(man)
endif()


set(PAM_U2F_SOURCES
        pam-u2f.c
        b64.c
        debug.c
        expand.c
        explicit_bzero.c
        util.c
)
add_library(pam_u2f SHARED ${PAM_U2F_SOURCES})
set_target_properties(pam_u2f PROPERTIES OUTPUT_NAME pam_u2f)

target_link_libraries(pam_u2f ${FIDO2_LIBRARIES} ${CRYPTO_LIBRARIES} ${PAM_LIBRARIES})

install(TARGETS pam_u2f
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
