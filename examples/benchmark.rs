use rand::RngCore;

/// Size of the random data to generate.
const BLOCK_SIZE: usize = 1024 * 1024 * 512;

/// Number of scans to perform. (on different random data)
const BLOCKS: usize = 5;

/// This example benchmarks the scan performance in a single-threaded and
/// multi-threaded context.
///
/// The example generates a random data buffer, and then scans it for a pattern.
///
/// The scan is performed multiple times, and the total (scan-only) time is measured.
fn main() {
    println!("Blocks: {} x {:#02x} bytes", BLOCKS, BLOCK_SIZE);

    let mut time = run_multi_threaded();
    println!(
        "Multi-threaded: {:?} @ {:.2} GB/s",
        time,
        get_gbps(time, BLOCK_SIZE * BLOCKS)
    );

    time = run_single_threaded();
    println!(
        "Single-threaded: {:?} @ {:.2} GB/s",
        time,
        get_gbps(time, BLOCK_SIZE * BLOCKS)
    );
}

fn run_single_threaded() -> std::time::Duration {
    let mut total_time = std::time::Duration::new(0, 0);

    for _ in 0..5 {
        let data = random_bytes(1024 * 1024 * 512 /* 512MB */);
        let start = std::time::Instant::now();

        aobscan::PatternBuilder::from_ida_style("48 8B ? ? ? ? ?")
            .unwrap()
            .with_threads(1)
            .unwrap()
            .build()
            .scan(&data, move |_| {
                true // Return true to continue scanning for other matches
            });

        let end = std::time::Instant::now();
        total_time += end - start;
    }

    total_time
}

fn run_multi_threaded() -> std::time::Duration {
    let mut total_time = std::time::Duration::new(0, 0);

    for _ in 0..5 {
        let data = random_bytes(1024 * 1024 * 512 /* 512MB */);
        let start = std::time::Instant::now();

        aobscan::PatternBuilder::from_ida_style("48 8B ? ? ? ? ?")
            .unwrap()
            .with_all_threads()
            .build()
            .scan(&data, move |_| {
                true // Return true to continue scanning for other matches
            });

        let end = std::time::Instant::now();
        total_time += end - start;
    }

    total_time
}

//noinspection ALL
fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Gets the GB/s from a time duration and byte count.
fn get_gbps(time: std::time::Duration, bytes: usize) -> f64 {
    let bytes_per_second = bytes as f64 / time.as_secs_f64();
    let gbps = bytes_per_second / 1024.0 / 1024.0 / 1024.0;
    gbps
}
