"""
Tests to verify package configuration and prevent packaging issues.

These tests ensure that all Python packages are correctly declared in
pyproject.toml, preventing ImportError when installed from PyPI.
"""

import pathlib
import tomllib


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
