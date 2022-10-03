/// This example demonstrates the easiest way to scan a file for a pattern.
/// The file is first read into memory, and then the pattern is scanned in
/// its entirety.
///
/// Threading: Multi-threaded
/// Hits: All
fn main() {
    let data = std::fs::read("test.bin").unwrap();

    let scan = aobscan::PatternBuilder::from_ida_style("48 8B ? ? ? ? ? 48 8B 88")
        .unwrap()
        .with_all_threads()
        .build()
        .scan(data.as_slice(), move |offset| {
            println!("Found pattern at offset {:#02x}", offset);
            true // Return true to continue scanning for other matches
        });

    println!("Found: {}", scan);
}
