use common::*;

mod common;

#[test]
/// Tests that the single-threaded scanner can find a pattern with no wildcards.
fn ida_scan_single_threaded() {
    // Create a random data buffer.
    let random_bytes = random_bytes(1024 * 1024 /* 1 MB */);

    // This is an AOB we want to find in the data.
    // It is going to be placed in the data buffer at the offset 0x2000.
    let target_offset = 0x1000;
    let known = b"\x55\x48\x89\xE5\x48\x8B";

    unsafe {
        // Copy the known bytes to the random data buffer.
        std::ptr::copy(
            known.as_ptr(),
            random_bytes.as_ptr().offset(target_offset) as *mut u8,
            known.len(),
        );
    }

    // Match all the bytes.
    // This is not really a pattern, but it is a good test case.
    let mut correct = false;
    let result = aobscan::PatternBuilder::from_ida_style("55 48 89 E5 48 8B")
        .unwrap()
        .with_all_threads()
        .build()
        .scan(&random_bytes, |offset| {
            if offset as isize == target_offset { correct = true; }
            true
        });

    assert!(correct);
    assert!(result);
}
