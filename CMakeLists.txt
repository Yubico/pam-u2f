# Copyright (C) 2025 Yubico AB - See COPYING

cmake_minimum_required(VERSION 3.18.0)

project(
	pam_u2f
	VERSION 1.4.0
	HOMEPAGE_URL https://developers.yubico.com/pam-u2f/
	LANGUAGES C
)

set(PROJECT_BUGREPORT https://github.com/Yubico/pam-u2f/issues)

find_package(PkgConfig REQUIRED)
include(CMakePushCheckState)
include(CheckCCompilerFlag)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CTest)
include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(DEFAULT_PAM_DIR ${CMAKE_INSTALL_FULL_LIBDIR})
if (CMAKE_SYSTEM_NAME STREQUAL Linux)
	string(APPEND DEFAULT_PAM_DIR /security)
elseif (CMAKE_SYSTEM_NAME STREQUAL Darwin)
	string(APPEND DEFAULT_PAM_DIR /pam)
endif()

set(DEFAULT_SCONF_DIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/security)

option(BUILD_MODULE    "Build pam_u2f.so"                ON)
option(BUILD_MANPAGES  "Build man pages"                 ON)
option(BUILD_PAMU2FCFG "Build pamu2fcfg"                 ON)
option(BUILD_FUZZER    "Build fuzzer"                    OFF)
option(ENABLE_DIST     "Enable dist target"              OFF)
set(SCONF_DIR ${DEFAULT_SCONF_DIR} CACHE PATH "Path to module configuration file")
set(PAM_DIR   ${DEFAULT_PAM_DIR}   CACHE PATH "Where to install the PAM module")

message(STATUS "OPTIONS:")
message(STATUS "  BUILD_MODULE:    ${BUILD_MODULE}")
message(STATUS "  BUILD_MANPAGES:  ${BUILD_MANPAGES}")
message(STATUS "  BUILD_PAMU2FCFG: ${BUILD_PAMU2FCFG}")
message(STATUS "  BUILD_TESTING:   ${BUILD_TESTING}")
message(STATUS "  BUILD_FUZZER:    ${BUILD_FUZZER}")
message(STATUS "  ENABLE_DIST:     ${ENABLE_DIST}")
message(STATUS "  SCONF_DIR:       ${SCONF_DIR}")
message(STATUS "  PAM_DIR:         ${PAM_DIR}")

add_library(common INTERFACE)

target_compile_features(common INTERFACE c_std_11)
target_compile_options(common INTERFACE
	-Wall
	-Wbad-function-cast
	-Wcast-qual
	-Wconversion
	-Wextra
	-Wformat-nonliteral
	-Wformat-security
	-Wformat=2
	-Wmissing-declarations
	-Wmissing-prototypes
	 # Because pam headers are doing sign-conversion, see
	 # PAM_MODUTIL_DEF_PRIVS in pam_modutil.h
	-Wno-sign-conversion
	-Wnull-dereference
	-Wpedantic
	-Wpointer-arith
	-Wshadow
	-Wstrict-prototypes
	-Wwrite-strings

	# Prevent __FILE__ to be expanded with full path
	-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=
)

if (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR
    CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
	target_compile_options(common INTERFACE -Wno-extra-semi)
endif()

cmake_push_check_state(RESET)
	set(CMAKE_REQUIRED_DEFINITIONS
		-D_DARWIN_C_SOURCE=1
		-D_GNU_SOURCE=1
		-D_NETBSD_SOURCE=1
		-D_OPENBSD_SOURCE=1
		-D__STDC_WANT_LIB_EXT1__=1
	)
	check_symbol_exists(explicit_bzero string.h HAVE_EXPLICIT_BZERO)
	check_symbol_exists(memset_s string.h HAVE_MEMSET_S)
	check_symbol_exists(readpassphrase readpassphrase.h HAVE_READPASSPHRASE)
	check_symbol_exists(secure_getenv stdlib.h HAVE_SECURE_GETENV)
	check_symbol_exists(strlcpy string.h HAVE_STRLCPY)
	foreach (v
		HAVE_EXPLICIT_BZERO
		HAVE_MEMSET_S
		HAVE_READPASSPHRASE
		HAVE_SECURE_GETENV
		HAVE_STRLCPY
	)
		if (${v})
			target_compile_definitions(common INTERFACE ${v})
		endif()
	endforeach()
	target_compile_definitions(common INTERFACE ${CMAKE_REQUIRED_DEFINITIONS})
cmake_pop_check_state()

find_package(PAM MODULE REQUIRED)
cmake_push_check_state(RESET)
	set(CMAKE_REQUIRED_LIBRARIES PAM::PAM)
	check_symbol_exists(openpam_borrow_cred security/pam_modules.h HAVE_OPENPAM_BORROW_CRED)
	check_symbol_exists(pam_modutil_drop_priv security/pam_modutil.h HAVE_PAM_MODUTIL_DROP_PRIV)
	foreach (v
		HAVE_OPENPAM_BORROW_CRED
		HAVE_PAM_MODUTIL_DROP_PRIV
	)
		if (${v})
			target_compile_definitions(common INTERFACE ${v})
		endif()
	endforeach()
cmake_pop_check_state()

pkg_check_modules(LibCrypto REQUIRED IMPORTED_TARGET libcrypto)
if (LibCrypto_VERSION VERSION_GREATER_EQUAL 3.0)
	# XXX Silence deprecation warnings for the EC_KEY_* family of functions.
	# This can be removed when we mandate libfido2 >=1.9.0 and switch to the EVP
	# interface.
	target_compile_definitions(PkgConfig::LibCrypto INTERFACE OPENSSL_API_COMPAT=0x10100000L)
endif()

pkg_check_modules(LibFido2 REQUIRED IMPORTED_TARGET libfido2>=1.3.0)

target_compile_definitions(common INTERFACE
	PACKAGE_BUGREPORT="${PROJECT_BUGREPORT}"
	PACKAGE_VERSION="${CMAKE_PROJECT_VERSION}"
	SCONFDIR="${SCONF_DIR}"
	HAVE_UNISTD_H  # assume always available
)

add_library(pam_u2f_base INTERFACE EXCLUDE_FROM_ALL)
target_compile_definitions(pam_u2f_base INTERFACE DEBUG_PAM=1 PAM_DEBUG=1)
target_include_directories(pam_u2f_base INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pam_u2f_base INTERFACE
	PkgConfig::LibCrypto
	PkgConfig::LibFido2
	PAM::PAM
	common
)

set(PAM_U2F_SOURCES
	pam-u2f.c
	b64.c
	cfg.c
	debug.c
	drop_privs.h
	expand.c
	util.c
	explicit_bzero.c
)
list(TRANSFORM PAM_U2F_SOURCES PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/)

if (BUILD_MODULE)
	add_library(pam_u2f MODULE ${PAM_U2F_SOURCES})
	set_target_properties(pam_u2f PROPERTIES PREFIX "")
	target_link_libraries(pam_u2f PRIVATE pam_u2f_base)

	if(APPLE AND (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR
	    CMAKE_C_COMPILER_ID STREQUAL "AppleClang"))
		target_link_options(pam_u2f PRIVATE
			-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/export.llvm
		)
	else()
		target_link_options(pam_u2f PRIVATE
			-Wl,--version-script -Wl,${CMAKE_CURRENT_SOURCE_DIR}/export.gnu
		)
	endif()
	install(TARGETS pam_u2f LIBRARY DESTINATION ${PAM_DIR})
endif()

if (BUILD_MANPAGES)
	add_subdirectory(man)
endif()

if (BUILD_PAMU2FCFG)
	add_subdirectory(pamu2fcfg)
endif()

if (BUILD_TESTING)
	enable_testing()
	add_subdirectory(tests)
endif()

if (BUILD_FUZZER)
	add_subdirectory(fuzz)
endif()

if (ENABLE_DIST)
	find_program(GIT git REQUIRED)

	set(DIST_PREFIX  ${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION})
	set(DIST_FORMAT  tar.gz)
	set(DIST_AR_OPTS -9)
	set(DIST_TAG     ${DIST_PREFIX})
	set(DIST_TARBALL ${DIST_PREFIX}.${DIST_FORMAT})

	add_custom_command(
		OUTPUT ${DIST_TARBALL}
		COMMAND
			${GIT}
				-C ${CMAKE_CURRENT_SOURCE_DIR}
				archive
				--prefix=${DIST_PREFIX}/
				--format ${DIST_FORMAT}
				--output ${CMAKE_CURRENT_BINARY_DIR}/${DIST_TARBALL}
				${DIST_AR_OPTS}
				${DIST_TAG}
	)
	add_custom_target(dist DEPENDS ${DIST_TARBALL})
endif()
