from typing import Dict, List, Optional, Type, Union
from regipy.plugins.plugin import Plugin
from regipy.registry import RegistryHive


VALIDATION_CASES = set()


class ValidationCase:

    input_hive: RegistryHive = None
    plugin: Plugin = None

    plugin_instance: Type[Plugin] = None

    # Will hold the output of the plugin execution
    plugin_output: List = None

    # These entries will be tested for presence in the plugin output
    expected_entries: List[Dict] = []

    # The result here will be matched to the
    exact_expected_result: Optional[Union[Dict, List]] = None

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
            self.exact_expected_result is not None or self.expected_entries
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

        output_entries_count = len(self.plugin_output)
        assert (
            self.expected_entries_count == output_entries_count
        ), f"No match for expected entries count: expected {self.expected_entries_count}, got {output_entries_count}"

        print(f"\tValidation passed for {self.plugin.NAME}")
