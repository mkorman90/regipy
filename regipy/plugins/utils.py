import jsonlines

import attr
from tqdm import tqdm

from regipy.plugins.plugin import PLUGINS


def dump_hive_to_json(registry_jhive, output_path, name_key_entry, verbose=False):
    with jsonlines.open(output_path, mode='w') as writer:
        for entry in tqdm(registry_jhive.recurse_subkeys(name_key_entry, as_json=True), disable=not verbose):
            writer.write(attr.asdict(entry))


def run_relevant_plugins(registry_hive, as_json=False, plugins=None):
    """
    Execute the relevant plugins on the hive
    :param registry_hive: a RegistryHive object
    :param as_json: Whether to return result as json
    :param plugins: List of plugin to execute (names according to the NAME field in each plugin)
    :return: The result, as dict
    """
    plugin_results = {}
    for plugin_class in PLUGINS:
        plugin = plugin_class(registry_hive, as_json=as_json)

        # If the list of plugins is defined, but the plugin is not in the list skip it.
        if plugins and not plugin.NAME in plugins:
            continue

        if plugin.can_run():
            plugin.run()
            plugin_results[plugin.NAME] = plugin.entries
    return plugin_results


