from collections import defaultdict
from dataclasses import dataclass, asdict
from contextlib import contextmanager

from tabulate import tabulate

import os
from pathlib import Path
from typing import List
from regipy.plugins.plugin import PLUGINS
from regipy.registry import RegistryHive
from regipy_tests.validation.utils import extract_lzma
from regipy_tests.validation.validation import VALIDATION_CASES, ValidationCase, ValidationResult


test_data_dir = str(Path(__file__).parent.parent.joinpath("data"))
validation_results_output_file = str(Path(__file__).parent.joinpath("plugin_validation.md"))


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
        return plugin_validation_case_instance.validate()
    except AssertionError as ex:
        raise PluginValidationCaseFailureException(
            f"Validation for {plugin_validation_case_instance.__class__.__name__} failed: {ex}"
        )


def run_validations_for_hive_file(hive_file_name, validation_cases) -> List[ValidationResult]:
    validation_results = []
    with load_hive(hive_file_name) as registry_hive:
        for validation_case in validation_cases:
            validation_results.append(validate_case(validation_case, registry_hive))
    return validation_results


def main():
    # Map all existing validation cases
    validation_cases = {v.plugin.NAME: v for v in VALIDATION_CASES}

    print(f"[*] Loaded {len(validation_cases)} validation cases")

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

    # Execute grouped by file, to save performance on extracting and loading the hive
    print("\n\nRunning Validations:")
    validation_results = []
    for registry_hive_file_name, validation_cases in registry_hive_map.items():
        print(
            f"\n\t[*] Validating {registry_hive_file_name} ({len(validation_cases)} validations):"
        )
        validation_results.extend(run_validations_for_hive_file(registry_hive_file_name, validation_cases))

    print()
    print(tabulate([asdict(v) for v in validation_results], headers='keys', tablefmt='markdown'))
    # TODO: Add to table all plugins without validation
    # TODO: Generate markdown file `validation_results_output_file`


if __name__ == "__main__":
    main()
