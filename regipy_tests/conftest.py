import lzma
import os

from pathlib import Path
from tempfile import mktemp

import pytest


def extract_lzma(path):
    tempfile_path = mktemp()
    with open(tempfile_path, "wb") as tmp:
        with lzma.open(path) as f:
            tmp.write(f.read())
    return tempfile_path


@pytest.fixture()
def temp_output_file():
    tempfile_path = mktemp()
    yield tempfile_path
    os.remove(tempfile_path)


@pytest.fixture(scope="module")
def test_data_dir():
    return str(Path(__file__).parent.joinpath("data"))


@pytest.fixture(scope="module")
def ntuser_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "NTUSER.DAT.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def software_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SOFTWARE.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def system_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SYSTEM.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def sam_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SAM.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def security_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SECURITY.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def amcache_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "amcache.hve.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def bcd_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "BCD.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def second_hive_path(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "NTUSER_modified.DAT.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def transaction_ntuser(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "transactions_NTUSER.DAT.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def transaction_log(test_data_dir):
    temp_path = extract_lzma(
        os.path.join(test_data_dir, "transactions_ntuser.dat.log1.xz")
    )
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def transaction_system(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SYSTEM_B.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def system_tr_log_1(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SYSTEM_B.LOG1.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def system_tr_log_2(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SYSTEM_B.LOG2.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def transaction_usrclass(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "UsrClass.dat.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def usrclass_tr_log_1(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "UsrClass.dat.LOG1.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def usrclass_tr_log_2(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "UsrClass.dat.LOG2.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def ntuser_software_partial(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "ntuser_software_partial.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def corrupted_system_hive(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "corrupted_system_hive.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def system_devprop(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SYSTEM_2.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def ntuser_hive_2(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "NTUSER_with_winscp.DAT.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def shellbags_ntuser(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "NTUSER_BAGMRU.DAT.xz"))
    yield temp_path
    os.remove(temp_path)


@pytest.fixture(scope="module")
def system_hive_with_filetime(test_data_dir):
    temp_path = extract_lzma(os.path.join(test_data_dir, "SYSTEM_WIN_10_1709.xz"))
    yield temp_path
    os.remove(temp_path)
