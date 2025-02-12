# Copyright (C) 2025 Yubico AB - See COPYING

pkg_check_modules(PAM QUIET IMPORTED_TARGET pam)

if (PAM_FOUND)
	add_library(PAM::PAM ALIAS PkgConfig::PAM)
else()
	find_library(PAM_LINK_LIBRARIES NAMES pam REQUIRED)
	find_path(PAM_INCLUDE_DIRS NAMES security/pam_modules.h)

	add_library(PAM::PAM UNKNOWN IMPORTED)

	set_target_properties(PAM::PAM PROPERTIES
		IMPORTED_LOCATION "${PAM_LINK_LIBRARIES}"
		INTERFACE_INCLUDE_DIRECTORIES "${PAM_INCLUDE_DIRS}"
	)
endif()

find_package_handle_standard_args(PAM
	REQUIRED_VARS PAM_LINK_LIBRARIES PAM_INCLUDE_DIRS
	VERSION_VAR PAM_VERSION
)
