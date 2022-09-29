use common::*;

mod common;

#[test]
/// Tests that the multi-threaded scanner can find a certain pattern in a random byte array,
/// using both IDA and code style signatures.
fn scan_multi_threaded() {
    // Create a random data buffer.
    let random_bytes = random_bytes(1024 * 1024 /* 1 MB */);

    // This is an AOB we want to find in the data.
    // It is going to be placed in the data buffer at the offset 0x2000.
    let target_offset = 0x2000;
    let known = b"\x55\x48\x89\xE5\x48\x8B\x00\x00\x00\x00\x00\x8B\x04\x07\x5D\xC3\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x50\x49\x89\xFE";

    unsafe {
        // Copy the known bytes to the random data buffer.
        std::ptr::copy(
            known.as_ptr(),
            random_bytes.as_ptr().offset(target_offset) as *mut u8,
            known.len(),
        );
    }

    // Run the IDA-style AOB scan.
    let mut correct = false;
    let mut result = aobscan::PatternBuilder::new()
        .ida_style("55 48 89 E5 ? 8B ? ? 00 ? ? 8B ? ? 5D C3")
        .unwrap()
        .with_all_threads()
        .build()
        .scan(&random_bytes, |offset| {
            if offset as isize == target_offset { correct = true; }
            true
        });

    assert!(correct);
    assert!(result);

    // Run the code-style AOB scan.
    correct = false;
    result = aobscan::PatternBuilder::new()
        .code_style(
            b"\x55\x48\x89\xE5\x00\x8B\x00\x00\x00\x00\x00\x8B\x00\x00\x5D\xC3",
            "....?.??.??.??..",
        )
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
