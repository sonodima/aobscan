fn main() {
    let data = std::fs::read("/Applications/CrossOver.app/Contents/MacOS/CrossOver").unwrap();

    let scan = aobscan::PatternBuilder::from_ida_style("48 8B ? ? ? ? ?")
        .unwrap()
        .with_threads(1)
        .unwrap()
        .build()
        .scan_object(&data, "__text", move |offset| {
            println!("Found pattern at offset {:#02x}", offset);
            true // Return true to continue scanning for other matches
        })
        .unwrap();

    println!("Found: {}", scan);
}
