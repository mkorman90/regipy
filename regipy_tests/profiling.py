import cProfile
import io
import lzma
import os
import pstats
from contextlib import contextmanager
from pathlib import Path
from pstats import SortKey
from tempfile import mktemp

import logbook

from regipy.registry import RegistryHive

logger = logbook.Logger(__name__)


@contextmanager
def profiling():
    pr = cProfile.Profile()
    pr.enable()
    yield
    pr.disable()
    s = io.StringIO()
    sortby = SortKey.CUMULATIVE
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats()
    print(s.getvalue())


@contextmanager
def get_file_from_tests(file_name):
    path = str(Path(__file__).parent.joinpath('data').joinpath(file_name))
    tempfile_path = mktemp()
    with open(tempfile_path, 'wb') as tmp:
        with lzma.open(path) as f:
            tmp.write(f.read())
    yield tempfile_path
    os.remove(tempfile_path)


registry_path = 'SAM.xz'
logger.info(f'Iterating over all subkeys in {registry_path}')
with profiling():
    with get_file_from_tests(registry_path) as reg:
        registry_hive = RegistryHive(reg)
        keys = [x for x in registry_hive.recurse_subkeys()]


