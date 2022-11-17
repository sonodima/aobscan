use aobscan::ObjectScan;

/// This example demonstrates how to use the `scan_object` function to scan a
/// specific section in an object file.
///
/// This example scans the `__text` section in a Mach-O macOS binary for four bytes,
/// starting with 48, followed by three variable bytes, and ending with 48.
///
/// Threading: Single-threaded
/// Hits: All
fn main() {
    // let data = std::fs::read("macho_binary").unwrap();
    let data = std::fs::read("macho_file").unwrap();
    let section_name = "__text";

    let scan = aobscan::PatternBuilder::from_hex_string("ffff488bbd70ffffffe9d1feffff4889de4b8b5c2c")
        .unwrap()
        .with_all_threads()
        .build()
        .scan_object(&data, section_name, move |result| {
            println!(
                "{:#02x} [{} {}+{:#02x}]",
                result.raw_offset,
                result.archive_id.unwrap_or("".to_string()),
                section_name,
                result.section_offset
            );

            true // Return true to continue scanning for other matches
        })
        .unwrap();

    println!("Found: {}", scan);
}
