from dataclasses import dataclass

from typing import Callable, Dict, List, Optional, Type, Union
from regipy.plugins.plugin import Plugin
from regipy.registry import RegistryHive


VALIDATION_CASES = set()


@dataclass
class ValidationResult:
    plugin_name: str
    plugin_class_name: str
    test_case_name: Optional[str]
    success: bool


class ValidationCase:

    input_hive: RegistryHive = None
    plugin: Plugin = None

    plugin_instance: Type[Plugin] = None

    # Will hold the output of the plugin execution
    plugin_output: Union[List, Dict] = None

    # These entries will be tested for presence in the plugin output
    expected_entries: List[Dict] = []

    # The result here will be matched to the
    exact_expected_result: Optional[Union[Dict, List]] = None

    # Optionally Implement a custom test for your plugin, which will be called during the validation step
    # This test can replace the validation of entries, but not the count.
    # The test must return True, or raise an AssertionError
    custom_test: Optional[Callable] = None

    # Expected entries count
    expected_entries_count: int = None

    def __init_subclass__(cls):
        VALIDATION_CASES.add(cls)

    def __init__(self, input_hive: RegistryHive) -> None:
        self.input_hive = input_hive

    def validate(self):
        print(
            f"\tStarting validation for {self.plugin.NAME} ({self.__class__.__name__})"
        )
        self.plugin_instance = self.plugin(self.input_hive, as_json=True)
        self.plugin_instance.run()
        self.plugin_output = self.plugin_instance.entries

        assert (
            self.exact_expected_result is not None
            or self.expected_entries is not None
            or self.custom_test is not None
        ), "Some output must be tested!"

        entries_found = True
        for entry in self.expected_entries:
            if entry not in self.plugin_output:
                entries_found = False

        assert entries_found

        if self.exact_expected_result:
            assert (
                self.plugin_output == self.exact_expected_result
            ), "Expected exact plugin output!"

        if self.custom_test is not None:
            self.custom_test()

        # If we are verifying an exact result, there is no need to verify entries count
        if not self.exact_expected_result:
            output_entries_count = len(self.plugin_output)
            assert (
                self.expected_entries_count == output_entries_count
            ), f"No match for expected entries count: expected {self.expected_entries_count}, got {output_entries_count}"

        print(f"\tValidation passed for {self.plugin.NAME}")
        return ValidationResult(
            plugin_name=self.plugin.NAME,
            plugin_class_name=self.plugin.__name__,
            test_case_name=self.__class__.__name__,
            success=True,
        )

    def debug(self):
        import ipdb

        ipdb.set_trace()
