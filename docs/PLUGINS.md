## regipy Plugins

* The plugin system is a robust and extensive feature that auto-detects the hive type and execute the relevant plugins.

To see a comprehensive list, please refer to the [Validation cases report](../validation/plugin_validation.md)

## Contributing new plugins
Adding a new plugin is very straight forward:
1. Copy the `regipy/plugins/plugin_template.py` file to the relevant folder (according to hive type)
2. Update the code:
   * Update the `NAME` parameter and the Class name accordingly (NAME in snake case, Class name in camel case)
   * Feel free to use/add any utility function to `regipy/utils.py` 
   * Import your class in `regipy/plugins/__init__.py`
3. Add a [validation case](../README.md#validation-cases). This is mandatory and replaces the old regipy tests.
