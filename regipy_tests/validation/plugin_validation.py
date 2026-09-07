import json
import os
import sys
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from tabulate import tabulate

from regipy.plugins.plugin import PLUGINS
from regipy.registry import RegistryHive
from regipy_tests.validation.utils import extract_lzma
from regipy_tests.validation.validation import (
    VALIDATION_CASES,
    ValidationCase,
    ValidationResult,
)

# Enable to raise exception on validation failure
# As we are currently not enforcing validations - no raising exceptions by default
ENFORCE_VALIDATION = True

# Generate a template for all plugins that have missing validation tests
GENERATE_MISSING_VALIDATION_TEST_TEMPLATES = False

# It is possible to get an ipdb breakpoint once an exception is raised, useful for debugging plugin results
# The user will be dropped into the validation case context, accessing all properties using `self`.
SHOULD_DEBUG = False


test_data_dir = str(Path(__file__).parent.parent.joinpath("data"))
validation_results_output_file = str(Path(__file__).parent.joinpath("plugin_validation.md"))
validated_plugins_json_file = str(Path(__file__).parent.parent.parent.joinpath("regipy/plugins/validated_plugins.json"))


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


def validate_case(plugin_validation_case: type[ValidationCase], registry_hive: RegistryHive):
    plugin_validation_case_instance: ValidationCase | None = None
    try:
        plugin_validation_case_instance = plugin_validation_case(registry_hive)
        return plugin_validation_case_instance.validate()
    except AssertionError as ex:
        assert plugin_validation_case_instance is not None
        msg = f"Validation for {plugin_validation_case_instance.__class__.__name__} failed: {ex}"
        if ENFORCE_VALIDATION:
            if SHOULD_DEBUG:
                print(f"[!] [ENFORCED] [DEBUG]: {msg}")
                plugin_validation_case_instance.debug()
            raise PluginValidationCaseFailureException(msg)
        else:
            print(f"[!] [NOT ENFORCED]: {msg}")
            if SHOULD_DEBUG:
                plugin_validation_case_instance.debug()


def run_validations_for_hive_file(hive_file_name, validation_cases) -> list[ValidationResult]:
    validation_results = []
    with load_hive(hive_file_name) as registry_hive:
        for validation_case in validation_cases:
            validation_results.append(validate_case(validation_case, registry_hive))
    return validation_results


def main():
    # Map all existing validation cases
    validation_cases_map: dict[str, type[ValidationCase]] = {v.plugin.NAME: v for v in VALIDATION_CASES}
    plugins_without_validation: set[str] = {p.NAME for p in PLUGINS if p.NAME is not None}.difference(
        set(validation_cases_map.keys())
    )

    print(f"[*] Loaded {len(validation_cases_map)} validation cases")

    if len(sys.argv) == 2:
        plugin_name = sys.argv[1]
        if plugin_name in validation_cases_map:
            print(f"Running validation for plugin {plugin_name}")
            validation_case_cls = validation_cases_map[plugin_name]
            with load_hive(validation_case_cls.test_hive_file_name) as registry_hive:
                validate_case(validation_case_cls, registry_hive)
                return
        print(f"No ValidationCase for {plugin_name}")
        return

    # Map all plugins according to registry hive test file, for performance.
    # Also, warn about plugins without validation, this will be enforced in the future.
    registry_hive_map: dict[str, list[type[ValidationCase]]] = defaultdict(list)
    for plugin in PLUGINS:
        plugin_name = plugin.NAME
        if plugin_name in validation_cases_map:
            print(f"[+] Plugin {plugin_name} has validation case")
            plugin_validation_case = validation_cases_map[plugin_name]

            # Get hive filename from file, in the future group plugin validation by hive file
            hive_file_name = plugin_validation_case.test_hive_file_name
            if hive_file_name is not None:
                registry_hive_map[hive_file_name].append(plugin_validation_case)
        else:
            print(f"[!] {plugin_name} has NO validation case!")

    # Execute grouped by file, to save performance on extracting and loading the hive
    print("\n\nRunning Validations:")
    validation_results: list[ValidationResult] = []
    for registry_hive_file_name, validation_cases in registry_hive_map.items():
        print(f"\n\t[*] Validating {registry_hive_file_name} ({len(validation_cases)} validations):")

        validation_results.extend(run_validations_for_hive_file(registry_hive_file_name, validation_cases))

    print()
    validation_results_dict: list[dict[str, object]] = sorted(
        [asdict(v) for v in validation_results], key=lambda x: x["plugin_name"]
    )
    print(f"\n[!] {len(validation_results_dict)}/{len(PLUGINS)} plugins have a validation case:")
    md_table_for_validation_results = tabulate(validation_results_dict, headers="keys", tablefmt="github")
    print(md_table_for_validation_results)

    if plugins_without_validation:
        print(f"\n[!] {len(plugins_without_validation)}/{len(PLUGINS)} plugins have no validation case!")
    # Create empty validation results for plugins without validation
    plugins_without_validation_results: list[dict[str, object]] = [
        asdict(
            ValidationResult(
                plugin_name=p.NAME or "",
                plugin_description=p.DESCRIPTION,
                plugin_class_name=p.__name__,
                test_case_name=None,
                success=False,
            )
        )
        for p in PLUGINS
        if p.NAME in plugins_without_validation
    ]
    md_table_for_plugins_without_validation_results = tabulate(
        sorted(plugins_without_validation_results, key=lambda x: str(x["plugin_name"])),
        headers="keys",
        tablefmt="github",
    )

    print(md_table_for_plugins_without_validation_results)
    if GENERATE_MISSING_VALIDATION_TEST_TEMPLATES:
        for p in PLUGINS:
            if p.NAME in plugins_without_validation:
                validation_template = f"""
from regipy.plugins.{p.COMPATIBLE_HIVE}.{p.__name__.lower()} import {p.__name__}
from regipy_tests.validation.validation import ValidationCase


class {p.__name__}ValidationCase(ValidationCase):
    plugin = {p.__name__}
    test_hive_file_name = "{p.COMPATIBLE_HIVE}.xz"
    exact_expected_result = None

            """
                plugin_name = p.NAME
                missing_test_target_path = str(
                    Path(__file__).parent.joinpath("validation_tests").joinpath(f"{plugin_name}_validation.py")
                )
                if not os.path.exists(missing_test_target_path):
                    print(f"Creating template for {plugin_name} target path: {missing_test_target_path}")
                    try:
                        with open(missing_test_target_path, "w+") as f:
                            f.write(validation_template)
                    except OSError as e:
                        print(f"Failed to write template: {e}")

    # If we are enforcing validation, raise on plugins without validation
    if not ENFORCE_VALIDATION and plugins_without_validation:
        # fmt: off
        raise PluginValidationCaseFailureException(
            f"{len(plugins_without_validation)} plugins are missing validation:"
            f" {[p.__name__ for p in PLUGINS if p.NAME in plugins_without_validation]}"
        )
    # fmt: on
    # Generate markdown file `validation_results_output_file`
    markdown_content = f"""
# Regipy plugin validation results

## Plugins with validation

{md_table_for_validation_results}

## Plugins without validation
**Starting regipy v5.0.0 - plugin validation replaces tests and is mandatary, being enforced by the build process**

{md_table_for_plugins_without_validation_results}
    """

    # Write the content to a Markdown file
    print(f" ** Updated the validation results in {validation_results_output_file} **")
    try:
        with open(validation_results_output_file, "w") as f:
            f.write(markdown_content)
    except OSError as e:
        print(f"Failed to write validation results: {e}")

    # Generate validated_plugins.json for the package
    validated_plugin_names = sorted(validation_cases_map.keys())
    print(f" ** Updated validated plugins JSON in {validated_plugins_json_file} **")
    try:
        with open(validated_plugins_json_file, "w") as f:
            json.dump(validated_plugin_names, f, indent=4)
    except OSError as e:
        print(f"Failed to write validated plugins JSON: {e}")


if __name__ == "__main__":
    main()
