# Copyright (c) 2024 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the COPYING file.
# SPDX-License-Identifier: BSD-2-Clause

macro(add_check NAME SOURCES LIB)
    add_executable(${NAME} ${SOURCES})
    add_test(NAME ${NAME} COMMAND ${NAME} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests)
    target_link_libraries(${NAME} ${LIB})
endmacro()

add_check(dlsym_check dlsym_check.c pam_u2f)
add_check(expand expand.c pam_u2f)
add_check(get_devices get_devices.c pam_u2f)

set_property(TEST dlsym_check PROPERTY ENVIRONMENT "PAM_U2F_MODULE=${CMAKE_BINARY_DIR}/libpam_u2f.so")
