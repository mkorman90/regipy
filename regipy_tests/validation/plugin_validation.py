from contextlib import contextmanager

import os
from pathlib import Path
from regipy.plugins.plugin import PLUGINS
from regipy.registry import RegistryHive
from regipy_tests.validation.utils import extract_lzma
from regipy_tests.validation.validation_tests import *
from regipy_tests.validation.validation import VALIDATION_CASES


test_data_dir = str(Path(__file__).parent.parent.joinpath("data"))


@contextmanager
def load_hive(hive_file_name):
    temp_path = extract_lzma(os.path.join(test_data_dir, hive_file_name))
    yield RegistryHive(temp_path)
    os.remove(temp_path)


# Map all existing validation cases
validation_cases = {v.plugin.NAME: v for v in VALIDATION_CASES}

print(f"[*] Loaded {len(validation_cases)} validation cases")

for plugin in PLUGINS:
    plugin_name = plugin.NAME
    if plugin_name in validation_cases:
        print(f"[+] Plugin {plugin_name} has validation case")
        plugin_validation_case = validation_cases[plugin_name]

        # Get hive filename from file, in the future group plugin validation by hive file
        hive_file_name = plugin_validation_case.test_hive_file_name

        with load_hive(hive_file_name) as registry_hive:
            plugin_validation_case_instance = plugin_validation_case(registry_hive)
            plugin_validation_case_instance.validate()

    else:
        print(
            f"[!] {plugin_name} has NO validation case (currently a warning) - will be enforced in the future!"
        )
