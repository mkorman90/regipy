## regipy Plugins

* The plugin system is a robust and extensive feature that auto-detects the hive type and execute the relevant plugins

### Plugins

#### System Hive
- [ ] persistence 
- [X] Installed services
- [X] List routes
- [X] Get computer name
- [X] Shimcache 
- [ ] Timezone data

#### NTUSER Hive
- [X] Persistence
- [ ] runmru
- [ ] Recent documents
- [ ] Typed URLs
- [X] User Assist
- [ ] Word Wheel Query

#### Amcache Hive
- [X] Parse amcache

#### SOFTWARE Hive
- [X] Persistence
- [ ] Installed programs
- [ ] Sysinternals EULA
- [ ] User SIDs
- [ ] Windows version info
- [X] Profile List

#### SAM Hive
- [ ] Users and groups

## Contributing new plugins
Adding a new plugin is very straight forward:
1. Copy the `regipy/plugins/plugin_template.py` file to the relevant folder (according to hive type)
2. Update the code:
   * Update the `NAME` parameter and the Class name accordingly (NAME in snake case, Class name in camel case)
   * Feel free to use/add any utility function to `regipy/utils.py` 
   * Import your class in `regipy/plugins/__init__.py`
