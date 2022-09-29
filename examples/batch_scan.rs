fn on_found(offset: usize) -> bool {
    println!("Found pattern at offset {:#02x}", offset);
    true // Return true to continue scanning for other matches
}

fn scan_batch(batch: &Vec<aobscan::Pattern>, data: &[u8]) {
    for pattern in batch.iter() {
        println!("Scanning for pattern: {}", pattern);
        pattern.scan(data, on_found);
    }
}

fn main() {
    let data = std::fs::read("test.bin").unwrap();

    // Mix multiple patterns with different styles together.
    let batch = vec![
        // IDA, all threads
        aobscan::PatternBuilder::new()
            .ida_style("48 8B ? ? ? ? ? 48 8B 88 ? ? ? ?")
            .unwrap()
            .with_all_threads()
            .build(),
        // Code, all thread
        aobscan::PatternBuilder::new()
            .code_style(
                b"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00",
                "...????...????",
            )
            .unwrap()
            .with_all_threads()
            .build(),
        // IDA, 1 thread
        aobscan::PatternBuilder::new()
            .ida_style("48 8B 88 ? ? ? ?")
            .unwrap()
            .with_threads(1)
            .unwrap()
            .build(),
    ];

    scan_batch(&batch, &data);
}
