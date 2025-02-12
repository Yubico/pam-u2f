# Copyright (C) 2025 Yubico AB - See COPYING

add_executable(pamu2fcfg
	pamu2fcfg.c
	strlcpy.c
	readpassphrase.c
	../util.c
	../b64.c
	../explicit_bzero.c
)

target_link_libraries(pamu2fcfg PRIVATE
	common
	PkgConfig::LibCrypto
	PkgConfig::LibFido2
	# TODO: Remove implicit dependency on PAM
	PAM::PAM
)

target_include_directories(pamu2fcfg PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
install(TARGETS pamu2fcfg)
