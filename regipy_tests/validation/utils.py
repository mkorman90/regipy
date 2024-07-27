import lzma
from tempfile import mktemp


def extract_lzma(path):
    tempfile_path = mktemp()
    with open(tempfile_path, 'wb') as tmp:
        with lzma.open(path) as f:
            tmp.write(f.read())
    return tempfile_path
