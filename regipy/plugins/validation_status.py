"""
Plugin validation status tracking.

This module tracks which plugins have been validated with test cases.
Plugins without validation may return invalid or incomplete data.
"""

import logging

logger = logging.getLogger(__name__)

# Set of plugin names that have validation test cases.
# This list is maintained by the validation test framework.
# Plugins not in this list should be used with caution.
VALIDATED_PLUGINS = {
    # Amcache
    "amcache",
    # BCD
    "boot_entry_list",
    # NTUSER
    "installed_programs_ntuser",
    "network_drives_plugin",
    "ntuser_classes_installer",
    "ntuser_persistence",
    "ntuser_shellbag_plugin",
    "terminal_services_history",
    "typed_paths",
    "typed_urls",
    "user_assist",
    "winrar_plugin",
    "winscp_saved_sessions",
    "word_wheel_query",
    "wsl",
    # SAM
    "local_sid",
    "samparse",
    # SECURITY
    "domain_sid",
    # SOFTWARE
    "app_paths",
    "disablesr_plugin",
    "execution_policy",
    "image_file_execution_options",
    "installed_programs_software",
    "last_logon_plugin",
    "networklist",
    "print_demon_plugin",
    "profilelist_plugin",
    "ras_tracing",
    "software_classes_installer",
    "software_plugin",
    "spp_clients_plugin",
    "susclient_plugin",
    "uac_plugin",
    "windows_defender",
    "winver_plugin",
    # SYSTEM
    "active_control_set",
    "backuprestore_plugin",
    "background_activity_moderator",
    "bootkey",
    "codepage",
    "computer_name",
    "crash_dump",
    "diag_sr",
    "disable_last_access",
    "host_domain_name",
    "lsa_packages",
    "mounted_devices",
    "network_data",
    "pagefile",
    "previous_winver_plugin",
    "processor_architecture",
    "routes",
    "safeboot_configuration",
    "services",
    "shimcache",
    "shutdown",
    "timezone_data",
    "timezone_data2",
    "usb_devices",
    "usbstor_plugin",
    "wdigest",
    # UsrClass
    "usrclass_shellbag_plugin",
}


def is_plugin_validated(plugin_name: str) -> bool:
    """Check if a plugin has validation test cases."""
    return plugin_name in VALIDATED_PLUGINS


def get_unvalidated_plugins(plugin_names: list[str]) -> list[str]:
    """Get list of plugin names that don't have validation."""
    return [name for name in plugin_names if name not in VALIDATED_PLUGINS]


def warn_unvalidated_plugin(plugin_name: str) -> None:
    """Log a warning for an unvalidated plugin."""
    logger.warning(
        f"Plugin '{plugin_name}' does not have a validation test case. "
        "Results may be incomplete or inaccurate. Use at your own discretion."
    )
