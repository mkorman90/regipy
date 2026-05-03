//! Dump every key's path + values_count, in walk order, for cross-validation.
//! Output: one line per key, "<values_count>\t<path>".

use std::io::{BufWriter, Write};

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_paths <hive>");
    let hive = regipy_core::Hive::open(&path).expect("open");
    let root = hive.root().expect("root");

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    walk(&root, "\\".into(), &mut out);
}

fn walk<W: Write>(nk: &regipy_core::NkRecord<'_>, path: String, out: &mut W) {
    writeln!(out, "{}\t{}", nk.values_count, path).unwrap();
    if nk.subkey_count == 0 {
        return;
    }
    for sk in nk.iter_subkeys() {
        let name = sk.name();
        let child_path = if path == "\\" {
            format!("\\{}", name)
        } else {
            format!("{}\\{}", path, name)
        };
        walk(&sk, child_path, out);
    }
}
