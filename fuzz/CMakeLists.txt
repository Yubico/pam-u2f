# Copyright (C) 2025 Yubico AB - See COPYING

add_library(pam_u2f_fuzz SHARED ${PAM_U2F_SOURCES} wrap.c)
target_link_options(pam_u2f_fuzz PRIVATE
	-Wl,--wrap=asprintf
	-Wl,--wrap=strdup
	-Wl,--wrap=calloc
	-Wl,--wrap=malloc
	-Wl,--wrap=open
	-Wl,--wrap=openat
	-Wl,--wrap=close
	-Wl,--wrap=fdopen
	-Wl,--wrap=fstat
	-Wl,--wrap=read
	-Wl,--wrap=gethostname
	-Wl,--wrap=getline
	-Wl,--wrap=getpwnam_r
	-Wl,--wrap=getpwuid_r
	-Wl,--wrap=geteuid
	-Wl,--wrap=secure_getenv
	-Wl,--wrap=pam_get_user
	-Wl,--wrap=pam_get_item
	-Wl,--wrap=pam_modutil_drop_priv
	-Wl,--wrap=pam_modutil_regain_priv
	-Wl,--wrap=BIO_new
	-Wl,--wrap=BIO_write
	-Wl,--wrap=BIO_read
	-Wl,--wrap=BIO_ctrl
	-Wl,--wrap=BIO_new_mem_buf
	-Wl,--wrap=EC_KEY_new_by_curve_name
	-Wl,--wrap=EC_KEY_get0_group
	-Wl,--wrap=fido_dev_open
	-Wl,--wrap=fido_dev_info_manifest

	-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/export.gnu
)

target_compile_options(pam_u2f_fuzz PRIVATE -fsanitize=fuzzer-no-link)
target_compile_definitions(pam_u2f_fuzz PRIVATE WITH_FUZZING)
target_link_libraries(pam_u2f_fuzz PUBLIC pam_u2f_base)

function(add_fuzzer NAME)
	add_executable(${NAME} ${ARGN})
	target_compile_options(${NAME} PRIVATE -fsanitize=fuzzer)
	target_link_libraries(${NAME} PRIVATE common pam_u2f_fuzz)
	target_link_options(${NAME} PRIVATE -fsanitize=fuzzer)
endfunction()

add_fuzzer(fuzz_format_parsers fuzz_format_parsers.c)
add_fuzzer(fuzz_auth fuzz_auth.c pack.c)
