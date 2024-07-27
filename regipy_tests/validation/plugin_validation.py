from collections import defaultdict
from contextlib import contextmanager

import os
from pathlib import Path
from regipy.plugins.plugin import PLUGINS
from regipy.registry import RegistryHive
from regipy_tests.validation.utils import extract_lzma
from regipy_tests.validation.validation import VALIDATION_CASES, ValidationCase


test_data_dir = str(Path(__file__).parent.parent.joinpath("data"))


class PluginValidationCaseFailureException(Exception):
    """
    raised when a plugin validation test case failed
    """

    pass


@contextmanager
def load_hive(hive_file_name):
    temp_path = extract_lzma(os.path.join(test_data_dir, hive_file_name))
    yield RegistryHive(temp_path)
    os.remove(temp_path)


def validate_case(plugin_validation_case: ValidationCase, registry_hive: RegistryHive):
    try:
        plugin_validation_case_instance = plugin_validation_case(registry_hive)
        plugin_validation_case_instance.validate()
    except AssertionError as ex:
        raise PluginValidationCaseFailureException(
            f"Validation for {plugin_validation_case_instance.__class__.__name__} failed: {ex}"
        )


def run_validations_for_hive_file(hive_file_name, validation_cases):
    with load_hive(hive_file_name) as registry_hive:
        for validation_case in validation_cases:
            validate_case(validation_case, registry_hive)


# Map all existing validation cases
validation_cases = {v.plugin.NAME: v for v in VALIDATION_CASES}

print(f"[*] Loaded {len(validation_cases)} validation cases")

# TODO: First map all validation tests and flag which plugins do not have one
# TODO: Then execute grouped by file, to save performance on extracting and loading the hive

# Map all plugins according to registry hive test file, for performance.
# Also, warn about plugins without validation, this will be enforced in the future.
registry_hive_map = defaultdict(list)
for plugin in PLUGINS:
    plugin_name = plugin.NAME
    if plugin_name in validation_cases:
        print(f"[+] Plugin {plugin_name} has validation case")
        plugin_validation_case = validation_cases[plugin_name]

        # Get hive filename from file, in the future group plugin validation by hive file
        hive_file_name = plugin_validation_case.test_hive_file_name
        registry_hive_map[hive_file_name].append(plugin_validation_case)
    else:
        print(
            f"[!] {plugin_name} has NO validation case (currently a warning) - will be enforced in the future!"
        )

print("\n\nRunning Validations:")
for registry_hive_file_name, validation_cases in registry_hive_map.items():
    print(
        f"\n\t[*] Validating {registry_hive_file_name} ({len(validation_cases)} validations):"
    )
    run_validations_for_hive_file(registry_hive_file_name, validation_cases)
