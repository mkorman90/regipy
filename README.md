# regipy

Regipy is a python library for parsing offline registry hives!

**Requires Python 3.9 or higher.**

Features:

* Use as a library
* Recurse over the registry hive, from root or a given path and get all subkeys and values
* Read specific subkeys and values
* Apply transaction logs on a registry hive
* Command Line Tools:
    * Dump an entire registry hive to json
    * Apply transaction logs on a registry hive
    * Compare registry hives
    * Execute plugins from a robust plugin system (i.e: amcache, shimcache, extract computer name...)

Project page: https://github.com/mkorman90/regipy

## Requirements

- Python 3.9 or higher

## Installation

Install regipy and the command line tools dependencies:

```bash
pip install regipy[cli]
```

For using regipy as a library only (fewer dependencies):

```bash
pip install regipy
```

For all features including shell bag parsing:

```bash
pip install regipy[full]
```

## Using as a library

```python
from regipy.registry import RegistryHive
reg = RegistryHive('/path/to/NTUSER.DAT')

# Iterate over a registry hive recursively:
for entry in reg.recurse_subkeys(as_json=True):
    print(entry)

# Iterate over a key and get all subkeys and their modification time:
for sk in reg.get_key('Software').get_subkeys():
    print(sk.name, convert_wintime(sk.header.last_modified).isoformat())

# Get values from a specific registry key:
reg.get_key('Software\\Microsoft\\Internet Explorer\\BrowserEmulation').get_values(as_json=True)

# Use plugins:
from regipy.plugins.ntuser.ntuser_persistence import NTUserPersistencePlugin
NTUserPersistencePlugin(reg, as_json=True).run()

# Run all supported plugins on a registry hive:
run_relevant_plugins(reg, as_json=True)
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
