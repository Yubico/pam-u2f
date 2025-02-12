# Copyright (C) 2025 Yubico AB - See COPYING

set(USERNAME $ENV{USER})
if (NOT DEFINED USERNAME)
	execute_process(
		COMMAND whoami
		OUTPUT_VARIABLE USERNAME
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endif()

function(expand_username FILE_NAME)
	configure_file(${FILE_NAME}.in ${FILE_NAME})
endfunction()

expand_username(credentials/new_double_-N.cred)
expand_username(credentials/new_double_-P-N.cred)
expand_username(credentials/new_double_-P.cred)
expand_username(credentials/new_double_-P-V-N.cred)
expand_username(credentials/new_double_-P-V.cred)
expand_username(credentials/new_double_-r-N.cred)
expand_username(credentials/new_double_-r-P-N.cred)
expand_username(credentials/new_double_-r-P.cred)
expand_username(credentials/new_double_-r-P-V-N.cred)
expand_username(credentials/new_double_-r-P-V.cred)
expand_username(credentials/new_double_-r.cred)
expand_username(credentials/new_double_-r-V-N.cred)
expand_username(credentials/new_double_-r-V.cred)
expand_username(credentials/new_double_.cred)
expand_username(credentials/new_double_-V-N.cred)
expand_username(credentials/new_double_-V.cred)
expand_username(credentials/new_mixed_12.cred)
expand_username(credentials/new_mixed_1-P2.cred)
expand_username(credentials/new_mixed_-P12.cred)
expand_username(credentials/new_mixed_-P1-P2.cred)
expand_username(credentials/new_-N.cred)
expand_username(credentials/new_-P-N.cred)
expand_username(credentials/new_-P.cred)
expand_username(credentials/new_-P-V-N.cred)
expand_username(credentials/new_-P-V.cred)
expand_username(credentials/new_-r-N.cred)
expand_username(credentials/new_-r-P-N.cred)
expand_username(credentials/new_-r-P.cred)
expand_username(credentials/new_-r-P-V-N.cred)
expand_username(credentials/new_-r-P-V.cred)
expand_username(credentials/new_-r.cred)
expand_username(credentials/new_-r-V-N.cred)
expand_username(credentials/new_-r-V.cred)
expand_username(credentials/new_.cred)
expand_username(credentials/new_-V-N.cred)
expand_username(credentials/new_-V.cred)
expand_username(credentials/old_credential.cred)
expand_username(credentials/ssh_credential.cred)
expand_username(credentials/new_limited_count.cred)
expand_username(credentials/empty.cred)

if (BUILD_MODULE)
	add_executable(dlsym_check dlsym_check.c)
	target_link_libraries(dlsym_check PRIVATE
		common
		${CMAKE_DL_LIBS}
	)
	add_test(NAME dlsym_check COMMAND dlsym_check)

	add_dependencies(dlsym_check pam_u2f)
	set_tests_properties(dlsym_check PROPERTIES
		ENVIRONMENT PAM_U2F_MODULE=$<TARGET_FILE:pam_u2f>
	)
endif()

add_library(pam_u2f_testing STATIC EXCLUDE_FROM_ALL ${PAM_U2F_SOURCES})
target_compile_definitions(pam_u2f_testing PRIVATE PAM_U2F_TESTING)
target_link_libraries(pam_u2f_testing PUBLIC pam_u2f_base)

add_executable(get_devices get_devices.c)
target_link_libraries(get_devices PRIVATE
	common
	pam_u2f_testing
)
add_test(NAME get_devices COMMAND get_devices)

add_executable(expand expand.c)
target_link_libraries(expand PRIVATE
	common
	pam_u2f_testing
)
add_test(NAME expand COMMAND expand)

add_executable(cfg cfg.c)
target_link_libraries(cfg PRIVATE
	common
	pam_u2f_testing
)
add_test(NAME cfg COMMAND cfg)
