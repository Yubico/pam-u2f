# Copyright (c) 2024 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the COPYING file.
# SPDX-License-Identifier: BSD-2-Clause

include_directories(.)

set(PAMU2FCFG_SOURCES
        pamu2fcfg.c
        readpassphrase.c
        strlcpy.c
        ../util.c
        ../b64.c
        ../explicit_bzero.c
)

add_executable(pamu2fcfg
        ${PAMU2FCFG_SOURCES}
)

target_link_libraries(pamu2fcfg ${FIDO2_LIBRARIES} ${CRYPTO_LIBRARIES} ${PAM_LIBRARIES})

install(TARGETS pamu2fcfg
        DESTINATION ${CMAKE_INSTALL_BINDIR})
