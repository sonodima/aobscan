fn main() {
    let data = include_bytes!("../test.bin");
    let start = std::time::Instant::now();

    let scan = aobscan::PatternBuilder::new()
        .ida_style("48 8B ? ? ? ? ? 48 8B 88 ? ? ? ?")
        .unwrap()
        .with_threads(1)
        .unwrap()
        .build()
        .scan(data, move |offset| {
            println!("Found pattern at offset {:#02x}", offset);
            true // Return true to continue scanning for other matches
        });

    let end = std::time::Instant::now();
    println!("Scan Time: {:?}", end - start);
    println!("Found: {}", scan);
}
