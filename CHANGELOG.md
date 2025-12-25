# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.0.0] - 2025-12-25

### Breaking Changes

- **Minimum Python version raised to 3.9** - Dropped support for Python 3.6, 3.7, and 3.8
- **Removed `attrs` dependency** - All data classes (`Cell`, `VKRecord`, `LIRecord`, `Value`, `Subkey`) now use Python's built-in `dataclasses` module instead of `attrs`
  - If you used `attr.asdict()` on these classes, switch to `dataclasses.asdict()`
  - If you used `attr.fields()` or other attrs introspection, switch to `dataclasses.fields()`
- **Removed `setup.py`** - Package now uses `pyproject.toml` exclusively (PEP 517/518)

### Added

- `pyproject.toml` with full PEP 621 metadata
- `py.typed` marker for PEP 561 type checking support
- Pre-commit configuration with ruff and mypy hooks
- Consolidated CI workflow with test matrix for Python 3.9-3.13
- Development documentation in README

### Changed

- Migrated from `flake8` to `ruff` for linting and formatting
- Modernized Python syntax throughout codebase (f-strings, type hints, import sorting)
- Consolidated GitHub Actions workflows into unified `ci.yml` and `publish.yml`
- Updated all GitHub Actions to latest versions (v4/v5)

### Removed

- `setup.py` (replaced by `pyproject.toml`)
- `.flake8` configuration (replaced by ruff config in `pyproject.toml`)
- Legacy GitHub workflow files (`python-package.yml`, `python-publish.yml`, `tests.yml`)

## [5.2.0] and earlier

See [GitHub Releases](https://github.com/mkorman90/regipy/releases) for previous versions.
