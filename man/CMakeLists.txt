# Copyright (c) 2024 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
# SPDX-License-Identifier: BSD-2-Clause

find_program(GZIP_PATH gzip)
find_program(A2X_PATH NAMES a2x a2x.py)
set(A2X_OPTS
        -D ${CMAKE_CURRENT_BINARY_DIR}
        -f manpage
        -L
        -a revdate="Version ${CMAKE_PROJECT_VERSION}"
)

set(MAN_NAMES pamu2fcfg.1 pam_u2f.8)

# man_gen
foreach(n ${MAN_NAMES})
    set(f ${CMAKE_CURRENT_SOURCE_DIR}/${n}.txt)
    add_custom_command(OUTPUT ${n}
            COMMAND ${A2X_PATH} ${A2X_OPTS} ${f}
            DEPENDS ${f})
    list(APPEND MAN_FILES ${n})
endforeach()

# man_gzip
foreach(f ${MAN_FILES})
    add_custom_command(OUTPUT ${f}.gz
            COMMAND gzip -cn ${f} > ${f}.gz
            DEPENDS ${f})
    list(APPEND GZ_FILES ${f}.gz)
endforeach()

add_custom_target(man_gen DEPENDS ${MAN_FILES})
add_custom_target(man_gzip DEPENDS ${GZ_FILES})
add_custom_target(man ALL)

if(GZIP_PATH)
    add_dependencies(man_gzip man_gen)
    add_dependencies(man man_gzip)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pamu2fcfg.1.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pam_u2f.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
else()
    add_dependencies(man man_gen)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pamu2fcfg.1.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pam_u2f.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
endif()
