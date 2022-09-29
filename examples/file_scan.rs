fn main() {
    let data = std::fs::read("test.bin").unwrap();
    let start = std::time::Instant::now();

    let scan = aobscan::PatternBuilder::new()
        .ida_style("48 8B ? ? ? ? ? 48 8B 88 ? ? ? ?")
        .unwrap()
        .with_all_threads()
        .build()
        .scan(data.as_slice(), move |offset| {
            println!("Found pattern at offset {:#02x}", offset);
            true // Return true to continue scanning for other matches
        });

    let end = std::time::Instant::now();
    println!("Scan Time: {:?}", end - start);
    println!("Found: {}", scan);
}
