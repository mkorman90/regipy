"""
LSA Packages plugin - Parses LSA security package configuration
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

LSA_PATH = r"Control\Lsa"


class LSAPackagesPlugin(Plugin):
    """
    Parses LSA (Local Security Authority) configuration from SYSTEM hive

    Provides information about:
    - Authentication packages
    - Security packages
    - Notification packages
    - Security provider DLLs

    These are common persistence and credential theft locations.

    Registry Key: Control\\Lsa under each ControlSet
    """

    NAME = "lsa_packages"
    DESCRIPTION = "Parses LSA security packages configuration"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started LSA Packages Plugin...")

        for controlset_path in self.registry_hive.get_control_sets(LSA_PATH):
            try:
                lsa_key = self.registry_hive.get_key(controlset_path)
            except RegistryKeyNotFoundException:
                logger.debug(f"Could not find LSA at: {controlset_path}")
                continue

            entry = {
                "key_path": controlset_path,
                "last_write": convert_wintime(lsa_key.header.last_modified, as_json=self.as_json),
            }

            for value in lsa_key.iter_values():
                name = value.name
                val = value.value

                if name == "Authentication Packages":
                    entry["authentication_packages"] = val if isinstance(val, list) else [val] if val else []
                elif name == "Security Packages":
                    entry["security_packages"] = val if isinstance(val, list) else [val] if val else []
                elif name == "Notification Packages":
                    entry["notification_packages"] = val if isinstance(val, list) else [val] if val else []
                elif name == "RunAsPPL":
                    entry["run_as_ppl"] = val == 1
                elif name == "DisableDomainCreds":
                    entry["disable_domain_creds"] = val == 1
                elif name == "LimitBlankPasswordUse":
                    entry["limit_blank_password_use"] = val == 1
                elif name == "NoLMHash":
                    entry["no_lm_hash"] = val == 1
                elif name == "LmCompatibilityLevel":
                    entry["lm_compatibility_level"] = val
                    entry["lm_compatibility_description"] = self._get_lm_compat_desc(val)
                elif name == "SecureBoot":
                    entry["secure_boot"] = val
                elif name == "auditbasedirectories":
                    entry["audit_base_directories"] = val == 1
                elif name == "auditbaseobjects":
                    entry["audit_base_objects"] = val == 1
                elif name == "CrashOnAuditFail":
                    entry["crash_on_audit_fail"] = val
                elif name == "FullPrivilegeAuditing":
                    entry["full_privilege_auditing"] = val

            # Check for OSConfig subkey
            try:
                osconfig_key = self.registry_hive.get_key(f"{controlset_path}\\OSConfig")
                for value in osconfig_key.iter_values():
                    if value.name == "Security Packages":
                        entry["osconfig_security_packages"] = (
                            value.value if isinstance(value.value, list) else [value.value] if value.value else []
                        )
            except RegistryKeyNotFoundException:
                pass

            self.entries.append(entry)

    @staticmethod
    def _get_lm_compat_desc(level: int) -> str:
        """Get description for LM compatibility level"""
        descriptions = {
            0: "Send LM & NTLM responses",
            1: "Send LM & NTLM - use NTLMv2 if negotiated",
            2: "Send NTLM response only",
            3: "Send NTLMv2 response only",
            4: "Send NTLMv2 response only, refuse LM",
            5: "Send NTLMv2 response only, refuse LM & NTLM",
        }
        return descriptions.get(level, f"Unknown level ({level})")
