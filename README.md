## regipy

[![CircleCI](https://circleci.com/gh/mkorman90/regipy.svg?style=shield)](https://circleci.com/gh/mkorman90/regipy)

Regipy is a python library for parsing offline registry hives. regipy has a lot of capabilities:
* Use as a library:
    * Recurse over the registry hive, from root or a given path and get all subkeys and values
    * Read specific subkeys and values
    * Apply transaction logs on a registry hive
* Command Line Tools
    * Dump an entire registry hive to json
    * Apply transaction logs on a registry hive
    * Compare registry hives
    * Execute plugins from a robust plugin system (i.e: amcache, shimcache, extract computer name...)

## Installation
Only python 3.6 and up is supported:

```bash
pip install regipy[cli]
```

NOTE: using pip with ``regipy[cli]`` instead of the plain ``regipy`` is a
significant change from version 1.9.x

For using regipy as a library, install only ``regipy`` which comes with fewer
dependencies:
```bash
pip install regipy
```


Also, it is possible to install from source by cloning the repository and executing:
```bash
pip install --editable .[cli]
```


## CLI

#### Parse the header:
```bash
registry-parse-header ~/Documents/TestEvidence/Registry/SYSTEM
```
Example output:
```
╒════════════════════════╤══════════╕
│ signature              │ b'regf'  │
├────────────────────────┼──────────┤
│ primary_sequence_num   │ 11639    │
├────────────────────────┼──────────┤
│ secondary_sequence_num │ 11638    │
├────────────────────────┼──────────┤
│ last_modification_time │ 0        │
├────────────────────────┼──────────┤
│ major_version          │ 1        │
├────────────────────────┼──────────┤
│ minor_version          │ 5        │
├────────────────────────┼──────────┤
│ file_type              │ 0        │
├────────────────────────┼──────────┤
│ file_format            │ 1        │
├────────────────────────┼──────────┤
│ root_key_offset        │ 32       │
├────────────────────────┼──────────┤
│ hive_bins_data_size    │ 10534912 │
├────────────────────────┼──────────┤
│ clustering_factor      │ 1        │
├────────────────────────┼──────────┤
│ file_name              │ SYSTEM   │
├────────────────────────┼──────────┤
│ checksum               │ 0        │
╘════════════════════════╧══════════╛
[2019-02-09 13:46:12.111654] WARNING: regipy.cli: Hive is not clean! You should apply transaction logs
```
* When parsing the header of a hive, also checksum validation and transaction validations are done


#### Dump entire hive to disk (this might take some time)
```bash
registry-dump ~/Documents/TestEvidence/Registry/NTUSER-CCLEANER.DAT -o /tmp/output.json
```
registry-dump util can also output a timeline instead of a JSON, by adding the `-t` flag


#### Run relevant plugins on Hive
```bash
registry-plugins-run ~/Documents/TestEvidence/Registry/SYSTEM -o /tmp/plugins_output.json
```
The hive type will be detected automatically and the relevant plugins will be executed. 
[**See the plugins section for more information**](docs/PLUGINS.md)

#### Compare registry hives
Compare registry hives of the same type and output to CSV (if `-o` is not specified output will be printed to screen)
```bash
registry-diff NTUSER.dat NTUSER_modified.dat -o /tmp/diff.csv
```
Example output:
```
[2019-02-11 19:49:18.824245] INFO: regipy.cli: Comparing NTUSER.DAT vs NTUSER_modified.DAT
╒══════════════╤══════════════╤════════════════════════════════════════════════════════════════════════════════╤════════════════════════════════════════════════╕
│ difference   │ first_hive   │ second_hive                                                                    │ description                                    │
╞══════════════╪══════════════╪════════════════════════════════════════════════════════════════════════════════╪════════════════════════════════════════════════╡
│ new_subkey   │              │ 2019-02-11T19:46:31.832134+00:00                                               │ \Software\Microsoft\legitimate_subkey          │
├──────────────┼──────────────┼────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ new_value    │              │ not_a_malware: c:\temp\legitimate_binary.exe @ 2019-02-11 19:45:25.516346+00:00 │ \Software\Microsoft\Windows\CurrentVersion\Run │
╘══════════════╧══════════════╧════════════════════════════════════════════════════════════════════════════════╧════════════════════════════════════════════════╛
[2019-02-11 19:49:18.825328] INFO: regipy.cli: Detected 2 differences
```

## Recover a registry hive, using transaction logs:
```bash
registry-transaction-logs NTUSER.DAT -p ntuser.dat.log1 -s ntuser.dat.log2 -o recovered_NTUSER.dat 
```
After recovering, compare the hives with registry-diff to see what changed

## Using as a library

#### Initiate the registry hive object
```
from regipy.registry import RegistryHive
reg = RegistryHive('/Users/martinkorman/Documents/TestEvidence/Registry/Vibranium-NTUSER.DAT')
```

#### Iterate recursively over the entire hive, from root key
```python
for entry in reg.recurse_subkeys(as_json=True):
    print(entry)
```

#### Iterate over a key and get all subkeys and their modification time:
```
for sk in reg.get_key('Software').iter_subkeys():
    print(sk.name, convert_wintime(sk.header.last_modified).isoformat())

Adobe 2019-02-03T22:05:32.525965
AppDataLow 2019-02-03T22:05:32.526047
McAfee 2019-02-03T22:05:32.526140
Microsoft 2019-02-03T22:05:32.526282
Netscape 2019-02-03T22:05:32.526352
ODBC 2019-02-03T22:05:32.526521
Policies 2019-02-03T22:05:32.526592
```

#### Get the values of a key:
```
reg.get_key('Software\Microsoft\Internet Explorer\BrowserEmulation').get_values(as_json=True)
[{'name': 'CVListTTL',
  'value': 0,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'UnattendLoaded',
  'value': 0,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'TLDUpdates',
  'value': 0,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'CVListXMLVersionLow',
  'value': 2097211,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'CVListXMLVersionHigh',
  'value': None,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'CVListLastUpdateTime',
  'value': None,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'IECompatVersionHigh',
  'value': None,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'IECompatVersionLow',
  'value': 2097211,
  'value_type': 'REG_DWORD',
  'is_corrupted': False},
 {'name': 'StaleCompatCache',
  'value': 0,
  'value_type': 'REG_DWORD',
  'is_corrupted': False}]
```

#### Use as a plugin:
```
from regipy.plugins.ntuser.ntuser_persistence import NTUserPersistencePlugin
NTUserPersistencePlugin(reg, as_json=True).run()

{
	'Software\\Microsoft\\Windows\\CurrentVersion\\Run': {
		'timestamp': '2019-02-03T22:10:52.655462',
		'values': [{
			'name': 'Sidebar',
			'value': '%ProgramFiles%\\Windows Sidebar\\Sidebar.exe /autoRun',
			'value_type': 'REG_EXPAND_SZ',
			'is_corrupted': False
		}]
	}
}
```

####  Run all relevant plugins for a specific hive
```
from regipy.plugins.utils import run_relevant_plugins
reg = RegistryHive('/Users/martinkorman/Documents/TestEvidence/Registry/SYSTEM')
run_relevant_plugins(reg, as_json=True)

{
	'routes': {},
	'computer_name': [{
		'control_set': 'ControlSet001\\Control\\ComputerName\\ComputerName',
		'computer_name': 'DESKTOP-5EG84UG',
		'timestamp': '2019-02-03T22:19:28.853219'
	}]
}


```
