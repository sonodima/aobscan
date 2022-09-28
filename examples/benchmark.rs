use rand::RngCore;

const BLOCK_SIZE: usize = 1024 * 1024 * 512;
const BLOCKS: usize = 5;

//noinspection ALL
fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn run_single_threaded() -> std::time::Duration {
    let mut total_time = std::time::Duration::new(0, 0);

    for _ in 0..5 {
        let data = random_bytes(1024 * 1024 * 512 /* 512MB */);
        let start = std::time::Instant::now();

        aobscan::Pattern::new()
            .ida_style("48 8B ? ? ? ? ?")
            .unwrap()
            .with_threads(1)
            .unwrap()
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

        aobscan::Pattern::new()
            .ida_style("48 8B ? ? ? ? ?")
            .unwrap()
            .with_all_threads()
            .scan(&data, move |_| {
                true // Return true to continue scanning for other matches
            });

        let end = std::time::Instant::now();
        total_time += end - start;
    }

    total_time
}

fn get_gbps(time: std::time::Duration, bytes: usize) -> f64 {
    let bytes_per_second = bytes as f64 / time.as_secs_f64();
    let gbps = bytes_per_second / 1024.0 / 1024.0 / 1024.0;
    gbps
}

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
