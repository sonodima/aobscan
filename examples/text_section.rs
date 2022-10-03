/// This example demonstrates how to use the `scan_object` function to scan a
/// specific section in an object file.
///
/// This example scans the `__text` section in a Mach-O macOS binary for four bytes,
/// starting with 48, followed by three variable bytes, and ending with 48.
///
/// Threading: Single-threaded
/// Hits: All
fn main() {
    let data = std::fs::read("macho_binary").unwrap();
    let section_name = "__text";

    let scan = aobscan::PatternBuilder::from_ida_style("48 ? ? ? 48")
        .unwrap()
        .with_threads(1)
        .unwrap()
        .build()
        .scan_object(&data, section_name, move |file_offset, section_offset| {
            println!("Found pattern at offset {:#02x} [{}+{:#02x}]", file_offset, section_name, section_offset);
            true // Return true to continue scanning for other matches
        })
        .unwrap();

    println!("Found: {}", scan);
}
