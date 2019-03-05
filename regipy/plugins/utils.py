from regipy.plugins.plugin import PLUGINS


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
            plugin_results[plugin.NAME] = plugin.run()
    return plugin_results


