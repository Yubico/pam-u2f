#  Copyright (C) 2025 Yubico AB - See COPYING

find_program(A2X a2x REQUIRED)

function(a2x_man MAN_NAME SECTION)
	set(MAN_DIR ${CMAKE_CURRENT_BINARY_DIR}/man${SECTION})
	set(MAN_FILE ${MAN_NAME}.${SECTION})
	set(MAN_TARGET ${MAN_DIR}/${MAN_FILE})
	set(MAN_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/${MAN_NAME}.${SECTION}.txt)

	make_directory(${MAN_DIR})
	add_custom_command(
		OUTPUT ${MAN_TARGET}
		COMMAND
			${A2X}
				--format=manpage
				--no-xmllint
				--attribute revdate="Version ${CMAKE_PROJECT_VERSION}"
				--attribute sconfdir="${SCONF_DIR}"
				--destination-dir ${MAN_DIR}
				${MAN_INPUT}
	)
	add_custom_target(man_${MAN_NAME}_${SECTION} ALL DEPENDS ${MAN_TARGET})
	install(FILES ${MAN_TARGET}
		DESTINATION ${CMAKE_INSTALL_MANDIR}/man${SECTION})

endfunction()

a2x_man(pamu2fcfg 1)
a2x_man(pam_u2f 8)
