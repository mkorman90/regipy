from collections import defaultdict
from dataclasses import dataclass, asdict
from contextlib import contextmanager

from tabulate import tabulate

import os
from pathlib import Path
from typing import Dict, List
from regipy.plugins.plugin import PLUGINS
from regipy.registry import RegistryHive
from regipy_tests.validation.utils import extract_lzma
from regipy_tests.validation.validation import (
    VALIDATION_CASES,
    ValidationCase,
    ValidationResult,
)


test_data_dir = str(Path(__file__).parent.parent.joinpath("data"))
validation_results_output_file = str(
    Path(__file__).parent.joinpath("plugin_validation.md")
)


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


def run_validations_for_hive_file(
    hive_file_name, validation_cases
) -> List[ValidationResult]:
    validation_results = []
    with load_hive(hive_file_name) as registry_hive:
        for validation_case in validation_cases:
            validation_results.append(validate_case(validation_case, registry_hive))
    return validation_results


def main():
    # Map all existing validation cases
    validation_cases: Dict[str, ValidationCase] = {
        v.plugin.NAME: v for v in VALIDATION_CASES
    }
    plugins_without_validation: set = {p.NAME for p in PLUGINS}.difference(
        set(validation_cases.keys())
    )

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
        validation_results.extend(
            run_validations_for_hive_file(registry_hive_file_name, validation_cases)
        )

    print()
    validation_results_dict = [asdict(v) for v in validation_results]
    print(
        f"\n[!] {len(validation_results_dict)}/{len(PLUGINS)} plugins have no validation case!"
    )
    md_for_validation_results = tabulate(
        validation_results_dict, headers="keys", tablefmt="mediawiki"
    )
    print(md_for_validation_results)

    print(
        f"\n[!] {len(plugins_without_validation)}/{len(PLUGINS)} plugins have no validation case!"
    )
    md_for_plugins_without_validation_results = tabulate(
        [
            asdict(
                ValidationResult(
                    plugin_name=p.NAME,
                    plugin_class_name=p.__name__,
                    test_case_name=None,
                    success=False,
                )
            )
            for p in PLUGINS
            if p.NAME in plugins_without_validation
        ],
        headers="keys",
        tablefmt="mediawiki",
    )
    print(md_for_plugins_without_validation_results)

    # Generate markdown file `validation_results_output_file`
    markdown_content = f"""
# Regipy plugin validation results

## Plugins with validation

{md_for_validation_results}

## Plugins without validation
**Please note that in the future, this check will be enforced for all plugins**

{md_for_plugins_without_validation_results}
    """

    # Write the content to a Markdown file
    print(f" ** Updated the validation results in {validation_results_output_file} **")
    with open(validation_results_output_file, "w") as f:
        f.write(markdown_content)


if __name__ == "__main__":
    main()
