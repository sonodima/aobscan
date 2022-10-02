#[test]
/// Test that the scanner can properly notify the caller when no matches are found.
fn scan_no_matches() {
    // Create an empty data buffer.
    let empty_data = [0u8; 1024 * 1024 /* 1 MB */];

    // Match all the bytes.
    // This data does not exist in the data buffer, so no matches should be found.
    let mut called = false;
    let result = aobscan::PatternBuilder::from_ida_style("55 48 89 E5 ? 8C")
        .unwrap()
        .with_all_threads()
        .build()
        .scan(&empty_data, |offset| {
            println!("Found match at offset 0x{:X}", offset);
            called = true;
            true
        });

    assert!(!called);
    assert!(!result);
}
