from typing import List, Type
from regipy.plugins.plugin import Plugin
from regipy.registry import RegistryHive


VALIDATION_CASES = set()

class ValidationCase():

    input_hive: RegistryHive = None
    plugin: Plugin = None

    plugin_instance: Type[Plugin] = None

    # Will hold the output of the plugin execution
    plugin_output: List = None

    # These entries will be tested for presence in the plugin output
    expected_entries: List = None

    # Expected entries count
    expected_entries_count: int = None

    def __init_subclass__(cls):
        VALIDATION_CASES.add(cls)


    def __init__(self, input_hive: RegistryHive) -> None:
        self.input_hive = input_hive

    def validate(self):
        print(f'\t[*] Starting validation for {self.plugin.NAME} ({self.__class__.__name__})')
        self.plugin_instance = self.plugin(self.input_hive, as_json=True)
        self.plugin_instance.run()
        self.plugin_output = self.plugin_instance.entries

        entries_found = True
        for entry in self.expected_entries:
            found_specific_entry = False
            if not entry in self.plugin_output:
                entries_found = False

        assert entries_found
        assert self.expected_entries_count == len(self.plugin_output)

        print(f'\t[*] Validation passed for {self.plugin.NAME} ({self.__class__.__name__})')
