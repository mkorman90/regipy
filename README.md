# regipy

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/mkorman90/regipy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/mkorman90/regipy)

> **⚠️ Breaking Changes in v6.0.0**
>
> Version 6.0.0 includes significant modernization changes:
> - **Python 3.9+ required** - Dropped support for Python 3.6, 3.7, and 3.8
> - **`attrs` library removed** - Data classes now use Python's built-in `dataclasses` module
> - If your code imports internal classes (`Cell`, `VKRecord`, `Value`, `Subkey`) and uses `attrs` functions like `attr.asdict()`, switch to `dataclasses.asdict()`
>
> See the [CHANGELOG](CHANGELOG.md) for full details.

Regipy is a python library for parsing offline registry hives (Hive files with REGF header). regipy has a lot of capabilities:
* Use as a library:
    * Recurse over the registry hive, from root or a given path and get all subkeys and values
    * Read specific subkeys and values
    * Apply transaction logs on a registry hive
* Command Line Tools
    * Dump an entire registry hive to json
    * Apply transaction logs on a registry hive
    * Compare registry hives
    * Execute plugins from a robust plugin system (i.e: amcache, shimcache, extract computer name...)

**Requires Python 3.9 or higher.**

## Installation

Regipy latest version can be installed from pypi:

```bash
pip install regipy[full]
```

NOTE: ``regipy[full]`` installs dependencies that require compilation tools and might take some time.
It is possible to install a version with relaxed dependencies, by omitting the ``[full]``.

Also, it is possible to install from source by cloning the repository and executing:
```bash
pip install --editable .[full]
```


## CLI

#### Parse the header:
```bash
regipy-parse-header ~/Documents/TestEvidence/Registry/SYSTEM
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
regipy-dump ~/Documents/TestEvidence/Registry/NTUSER-CCLEANER.DAT -o /tmp/output.json
```
regipy-dump util can also output a timeline instead of a JSON, by adding the `-t` flag


#### Run relevant plugins on Hive
```bash
regipy-plugins-run ~/Documents/TestEvidence/Registry/SYSTEM -o /tmp/plugins_output.json
```
The hive type will be detected automatically and the relevant plugins will be executed.
[**See the plugins section for more information**](docs/PLUGINS.md)

#### Compare registry hives
Compare registry hives of the same type and output to CSV (if `-o` is not specified output will be printed to screen)
```bash
regipy-diff NTUSER.dat NTUSER_modified.dat -o /tmp/diff.csv
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
regipy-process-transaction-logs NTUSER.DAT -p ntuser.dat.log1 -s ntuser.dat.log2 -o recovered_NTUSER.dat
```
After recovering, compare the hives with registry-diff to see what changed

## Using as a library

#### Initiate the registry hive object
```python
from regipy.registry import RegistryHive
reg = RegistryHive('/Users/martinkorman/Documents/TestEvidence/Registry/Vibranium-NTUSER.DAT')
```

#### Iterate recursively over the entire hive, from root key
```python
for entry in reg.recurse_subkeys(as_json=True):
    print(entry)
```

#### Iterate over a key and get all subkeys and their modification time:
```python
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
```python
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
```python
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

#### Run all relevant plugins for a specific hive
```python
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

## Validation cases
[Validation cases report](regipy_tests/validation/plugin_validation.md)

All new plugins should have one or more basic validation cases (which can be expanded in the future), for example:
```python
from regipy.plugins.system.bam import BAMPlugin
from regipy_tests.validation.validation import ValidationCase


class NTUserUserAssistValidationCase(ValidationCase):
    # define your plugin class
    plugin = BAMPlugin
    # define the test file name, which should be present in `regipy_tests/data`
    test_hive_file_name = "SYSTEM_WIN_10_1709.xz"

    # Use `expected_entries` to test for presence of a few samples from the plugin results
    expected_entries = [
        {
            "sequence_number": 9,
            "version": 1,
            "sid": "S-1-5-90-0-1",
            "executable": "\\Device\\HarddiskVolume2\\Windows\\System32\\dwm.exe",
            "timestamp": "2020-04-19T09:09:35.731816+00:00",
            "key_path": "\\ControlSet001\\Services\\bam\\state\\UserSettings\\S-1-5-90-0-1",
        }
    ]

    # OR use `exact_expected_result` to test for an exact result:
    exact_expected_result = [
        {
            "sequence_number": 9,
            "version": 1,
            "sid": "S-1-5-90-0-1",
            "executable": "\\Device\\HarddiskVolume2\\Windows\\System32\\dwm.exe",
            "timestamp": "2020-04-19T09:09:35.731816+00:00",
            "key_path": "\\ControlSet001\\Services\\bam\\state\\UserSettings\\S-1-5-90-0-1",
        },
        {
            "sequence_number": 8,
            "version": 1,
            "sid": "S-1-5-90-0-1",
            "executable": "\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe",
            "timestamp": "2020-04-19T09:09:34.544224+00:00",
            "key_path": "\\ControlSet001\\Services\\bam\\state\\UserSettings\\S-1-5-90-0-1",
        }
    ]

    expected_entries_count = 2
```

## Development

### Setting up for development

```bash
# Clone the repository
git clone https://github.com/mkorman90/regipy.git
cd regipy

# Install in development mode with all dependencies
pip install -e ".[full,dev]"

# Install pre-commit hooks
pre-commit install
```

### Running tests

```bash
# Run all tests
pytest

# Run specific test files
pytest regipy_tests/tests.py
pytest regipy_tests/cli_tests.py

# Run plugin validation
PYTHONPATH=. python regipy_tests/validation/plugin_validation.py
```

### Code quality

```bash
# Run linter
ruff check .

# Run formatter
ruff format .

# Run type checker
mypy regipy/
```

### Testing GitHub Actions Locally

To test CI workflow changes locally before pushing, use [act](https://github.com/nektos/act):

```bash
# Install act (Fedora)
sudo dnf install act-cli

# Install act (macOS)
brew install act

# Install act (other)
# See https://nektosact.com/installation/index.html
```

Make sure Docker is running, then:

```bash
# List available jobs
act -l

# Run the lint job
act -j lint

# Run all jobs for a push event
act push

# Run the test job with a specific Python version
act -j test

# Test the build job from publish workflow (simulates a release)
act release -j build --eventpath /dev/stdin <<< '{"action": "published"}'
```

Note: Some jobs may require secrets. You can provide them with:

```bash
act -j publish --secret PYPI_API_TOKEN=your_token
```

## License

MIT
