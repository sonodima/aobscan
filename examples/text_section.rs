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
    let data = std::fs::read("/Users/tommaso/Desktop/test").unwrap();
    let section_name = "__text";

    let scan = //aobscan::PatternBuilder::from_ida_style("48 ? ? ? 48")
        aobscan::PatternBuilder::from_hex_string("ffff488bbd70ffffffe9d1feffff4889de4b8b5c2c")
            .unwrap()
            .with_threads(1)
            .unwrap()
            .build()
            .scan_object(&data, section_name, move |result| {
                // println!("Found pattern {:#?}", result);
                println!(
                    "{:#02x} [{} - {}+{:#02x}]",
                    result.raw_offset,
                    result.archive_id.unwrap_or(""),
                    section_name,
                    result.section_offset
                );
                true // Return true to continue scanning for other matches
            })
            .unwrap();

    println!("Found: {}", scan);
}
