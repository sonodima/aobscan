fn main() {
    let data = std::fs::read("test.bin").unwrap();
    let slice = data.as_slice();

    let start = std::time::Instant::now();

    let scan = aobscan::Pattern::new()
        .ida_style("48 8B ? ? ? ? ? BB BB BB BB")
        .unwrap()
        .with_all_threads()
        .scan(slice, move |offset| {
            println!("Found pattern at offset {:#02x}", offset);
            true // Return true to continue scanning for other matches
        });

    let end = std::time::Instant::now();
    println!("Scan Time: {:?}", end - start);
    println!("Found: {}", scan);
}
