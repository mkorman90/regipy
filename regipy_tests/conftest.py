import lzma
import os
from contextlib import contextmanager

from pathlib import Path
from tempfile import mktemp

import pytest


def extract_lzma(path):
    tempfile_path = mktemp()
    with open(tempfile_path, 'wb') as tmp:
        with lzma.open(path) as f:
            tmp.write(f.read())
    return tempfile_path


@pytest.fixture()
def temp_output_file():
    tempfile_path = mktemp()
    yield tempfile_path
    os.remove(tempfile_path)


@pytest.fixture(scope='module')
def test_data_dir():
    return str(Path(__file__).parent.joinpath('data'))


@pytest.fixture(scope='module')
def ntuser_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, 'NTUSER.DAT.xz'))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope='module')
def software_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, 'SOFTWARE.xz'))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope='module')
def system_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, 'SYSTEM.xz'))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope='module')
def amcache_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, 'amcache.hve.xz'))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope='module')
def second_hive_path(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, 'NTUSER_modified.DAT.xz'))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope='module')
def transaction_ntuser(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, 'transactions_NTUSER.DAT.xz'))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope='module')
def transaction_log(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, 'transactions_ntuser.dat.log1.xz'))
    yield temp_path
    os.remove(temp_path)
