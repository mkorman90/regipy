"""
Tests to verify package configuration and prevent packaging issues.

These tests ensure that all Python packages are correctly declared in
pyproject.toml, preventing ImportError when installed from PyPI.
"""

import pathlib
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def test_all_packages_included_in_pyproject():
    """
    Verify all Python packages with __init__.py are listed in pyproject.toml.

    This catches the case where a new subpackage is added but not included
    in the packages list, which would cause ImportError when installed from PyPI.
    """
    # Find all packages (directories with __init__.py)
    regipy_root = pathlib.Path(__file__).parent.parent / "regipy"
    actual_packages = set()
    for init_file in regipy_root.rglob("__init__.py"):
        package_dir = init_file.parent
        # Convert path to dotted package name
        relative = package_dir.relative_to(regipy_root.parent)
        package_name = str(relative).replace("/", ".").replace("\\", ".")
        actual_packages.add(package_name)

    # Read packages from pyproject.toml
    pyproject_path = pathlib.Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)

    declared_packages = set(pyproject["tool"]["setuptools"]["packages"])

    # Check for missing packages
    missing = actual_packages - declared_packages
    assert not missing, f"Packages missing from pyproject.toml: {missing}"

    # Check for extra packages (declared but don't exist)
    extra = declared_packages - actual_packages
    assert not extra, f"Packages in pyproject.toml but don't exist: {extra}"


def test_all_packages_importable():
    """Test that all declared packages can be imported."""
    import importlib

    pyproject_path = pathlib.Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)

    packages = pyproject["tool"]["setuptools"]["packages"]

    for package in packages:
        try:
            importlib.import_module(package)
        except ImportError as e:
            raise AssertionError(f"Failed to import {package}: {e}") from e


def test_version_consistency():
    """
    Verify the version is consistent across all declaration sites.

    This catches a version bump that updates pyproject.toml but misses
    regipy/__init__.py or the top CHANGELOG.md entry, which would leave
    regipy.__version__ reporting a stale version.
    """
    import re

    import regipy

    repo_root = pathlib.Path(__file__).parent.parent

    # Version declared in pyproject.toml
    pyproject_path = repo_root / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)
    pyproject_version = pyproject["project"]["version"]

    # Runtime version attribute
    assert regipy.__version__ == pyproject_version, (
        f"regipy.__version__ ({regipy.__version__}) does not match pyproject.toml ({pyproject_version})"
    )

    # Top CHANGELOG.md entry (Keep a Changelog format)
    changelog_path = repo_root / "CHANGELOG.md"
    if changelog_path.exists():
        changelog = changelog_path.read_text(encoding="utf-8")
        match = re.search(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.MULTILINE)
        assert match, f"No version header found in {changelog_path}"
        changelog_version = match.group(1)
        assert changelog_version == pyproject_version, (
            f"CHANGELOG.md top entry ({changelog_version}) does not match pyproject.toml ({pyproject_version})"
        )
