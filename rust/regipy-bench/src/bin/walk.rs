use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "keys".into());
    let path = args.next().expect("usage: walk [keys|values] <hive>");
    let runs: u32 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    // Warm: open once to fault pages
    let hive = regipy_core::Hive::open(&path).expect("open");
    let warm = regipy_core::walk(&hive).expect("walk");
    eprintln!(
        "warm: keys={} values={} max_depth={}",
        warm.keys, warm.values, warm.max_depth
    );

    let mut times_ns: Vec<u128> = Vec::new();
    for _ in 0..runs {
        // Reopen each run to amortize parse cost (mmap remains warm in page cache)
        let hive = regipy_core::Hive::open(&path).expect("open");
        let t0 = Instant::now();
        let stats = match mode.as_str() {
            "keys" => regipy_core::walk(&hive).expect("walk"),
            "values" => regipy_core::walk_with_values(&hive).expect("walk"),
            other => panic!("unknown mode {}", other),
        };
        let dt = t0.elapsed().as_nanos();
        times_ns.push(dt);
        // Print stats for the last run
        eprintln!(
            "run: keys={} values={} max_depth={} ns={}",
            stats.keys, stats.values, stats.max_depth, dt
        );
    }
    times_ns.sort();
    let median = times_ns[times_ns.len() / 2];
    let min = *times_ns.first().unwrap();
    println!(
        "{{\"mode\":\"{}\",\"path\":\"{}\",\"runs\":{},\"min_ms\":{:.3},\"median_ms\":{:.3}}}",
        mode,
        path,
        runs,
        min as f64 / 1_000_000.0,
        median as f64 / 1_000_000.0
    );
}
