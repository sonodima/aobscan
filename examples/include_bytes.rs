/// This example demonstrates how to use the `include_bytes` macro to embed a file
/// into your binary, and then scan it for a pattern.
///
/// Threading: Single-threaded
/// Hits: All
fn main() {
    let data = include_bytes!("test.bin");

    let scan = aobscan::PatternBuilder::from_ida_style("48 8B ? ? ? ? ? 48 8B 88")
        .unwrap()
        .with_threads(1)
        .unwrap()
        .build()
        .scan(data, move |offset| {
            println!("Found pattern at offset {:#02x}", offset);
            true // Return true to continue scanning for other matches
        });

    println!("Found: {}", scan);
}
