fn main() {
    let data = std::fs::read("/Applications/CrossOver.app/Contents/MacOS/CrossOver").unwrap();
    let section_name = "__text";

    let scan = aobscan::PatternBuilder::from_ida_style("48 8B ? ? ? ? ?")
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
