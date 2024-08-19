# flake8: noqa
import cProfile
import io
import lzma
import os
import pstats
from contextlib import contextmanager
from pathlib import Path
from pstats import SortKey
from tempfile import mktemp

import logging

from regipy.registry import RegistryHive

logger = logging.getLogger(__name__)


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
    path = str(Path(__file__).parent.joinpath("data").joinpath(file_name))
    tempfile_path = mktemp()
    with open(tempfile_path, "wb") as tmp:
        with lzma.open(path) as f:
            tmp.write(f.read())
    yield tempfile_path
    os.remove(tempfile_path)


registry_path = "SYSTEM_2.xz"
print(f"Iterating over all subkeys in {registry_path}")
with profiling():
    with get_file_from_tests(registry_path) as reg:
        registry_hive = RegistryHive(reg)
        keys = [x for x in registry_hive.recurse_subkeys(fetch_values=False)]
print(f"Done.")

"""

=== Fetching subkey values:

Iterating over all subkeys in SYSTEM_2.xz
         6681282 function calls (6548808 primitive calls) in 21.406 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.009    0.009   21.440   21.440 /Users/martin/Projects/regipy/regipy_tests/profiling.py:47(<listcomp>)
115672/20016    0.326    0.000   21.431    0.001 /Users/martin/Projects/regipy/regipy/registry.py:126(recurse_subkeys)
    66844    1.067    0.000   19.524    0.000 /Users/martin/Projects/regipy/regipy/registry.py:413(iter_values)
    49779    0.280    0.000   10.845    0.000 /Users/martin/Projects/regipy/regipy/registry.py:378(read_value)
  1101844   10.603    0.000   10.603    0.000 {method 'read' of '_io.BytesIO' objects}
    30464    0.357    0.000    5.337    0.000 /Users/martin/Projects/regipy/regipy/utils.py:149(try_decode_binary)
   116294    3.587    0.000    5.021    0.000 {method 'decode' of 'bytes' objects}
   150968    0.252    0.000    2.785    0.000 /opt/anaconda3/envs/regipy/lib/python3.9/site-packages/construct/core.py:290(parse_stream)
187671/150968    0.117    0.000    2.359    0.000 /opt/anaconda3/envs/regipy/lib/python3.9/site-packages/construct/core.py:311(_parsereport)
    74151    0.051    0.000    1.779    0.000 /opt/anaconda3/envs/regipy/lib/python3.9/site-packages/construct/core.py:786(_parse)
    42243    0.024    0.000    1.434    0.000 /opt/anaconda3/envs/regipy/lib/python3.9/encodings/utf_16_le.py:15(decode)
    24363    0.039    0.000    1.413    0.000 /Users/martin/Projects/regipy/regipy/registry.py:322(iter_subkeys)
    42243    1.410    0.000    1.410    0.000 {built-in method _codecs.utf_16_le_decode}
    24367    0.116    0.000    1.333    0.000 /Users/martin/Projects/regipy/regipy/registry.py:350(_parse_subkeys)
    49779    0.026    0.000    0.943    0.000 :79(parseall)
    49779    0.579    0.000    0.917    0.000 :26(parse_struct_1)
    20015    0.127    0.000    0.837    0.000 /Users/martin/Projects/regipy/regipy/registry.py:292(__init__)
    20015    0.012    0.000    0.584    0.000 :124(parseall)
    20015    0.378    0.000    0.572    0.000 :23(parse_struct_1)
    

=== Without fetching subkeys:

Iterating over all subkeys in SYSTEM_2.xz
         2068855 function calls (1973084 primitive calls) in 5.288 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.037    0.037    4.969    4.969 /Users/martin/Projects/regipy/regipy_tests/profiling.py:47(<listcomp>)
115672/20016    0.462    0.000    4.932    0.000 /Users/martin/Projects/regipy/regipy/registry.py:126(recurse_subkeys)
    24363    0.097    0.000    4.104    0.000 /Users/martin/Projects/regipy/regipy/registry.py:324(iter_subkeys)
    24367    0.312    0.000    3.900    0.000 /Users/martin/Projects/regipy/regipy/registry.py:352(_parse_subkeys)
    48737    0.322    0.000    3.121    0.000 /opt/anaconda3/envs/regipy/lib/python3.9/site-packages/construct/core.py:290(parse_stream)
    48737    0.119    0.000    2.640    0.000 /opt/anaconda3/envs/regipy/lib/python3.9/site-packages/construct/core.py:311(_parsereport)
    20015    0.343    0.000    2.370    0.000 /Users/martin/Projects/regipy/regipy/registry.py:294(__init__)
    24372    0.038    0.000    2.334    0.000 /opt/anaconda3/envs/regipy/lib/python3.9/site-packages/construct/core.py:786(_parse)
    20015    0.033    0.000    1.683    0.000 :124(parseall)
    20015    1.123    0.000    1.650    0.000 :23(parse_struct_1)
     4353    0.045    0.000    0.610    0.000 :76(parseall)

"""
