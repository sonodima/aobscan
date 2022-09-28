use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Multi-threaded AOB memory scanner: scans for a pattern in the given slice.<br><br>
///
/// # Examples
///
/// ## Multi-threaded scan for an IDA-style pattern
/// ```
/// let data = std::fs::read("some.bin").unwrap();
/// let found = aobscan::Pattern::new()
///     .ida_style("48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ?")
///     .unwrap()
///     .with_all_threads()
///     .scan(&data, move |offset| {
///         println!("Match at offset {:#02x}", offset);
///         true // Return true to continue scanning for other matches
///     });
/// ```
///
/// ## Single-threaded scan for a code-style pattern
/// ```
/// let data = std::fs::read("some.bin").unwrap();
/// let found = aobscan::Pattern::new()
///     .code_style(b"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00", "...????...????")
///     .unwrap()
///     .with_threads(1)
///     .unwrap()
///     .scan(&data, move |offset| {
///         println!("Match at offset {:#02x}", offset);
///         true // Return true to continue scanning for other matches
///     });
/// ```
pub struct Pattern {
    signature: Vec<u8>,
    mask: Vec<bool>,
    threads: usize,
}

impl Pattern {
    /// Creates an empty single-threaded pattern.
    pub fn new() -> Self {
        Self {
            signature: Vec::new(),
            mask: Vec::new(),
            threads: 1,
        }
    }

    /// Initializes the pattern with a code-style signature.<br><br>
    ///
    /// A code-style signature is characterized by a byte array and a mask string.<br>
    /// The mask string is a list of characters, where each character represents whether
    /// the corresponding byte in the byte array is a wildcard or not.<br>
    /// You must use a `?` for each wildcard byte, but you can choose any other character
    /// for non-wildcard bytes.<br><br>
    ///
    /// The length of the mask string must be equal to the length of the byte array,
    /// and the byte array can contain any hexadecimal value in the place of a wildcard.<br><br>
    ///
    /// # Arguments
    /// * `signature` - The byte array containing the bytes to search for.
    /// * `mask` - The mask string.
    ///
    /// # Returns
    /// The current instance of the pattern, or `None` if the parameters are invalid.<br><br>
    ///
    /// # Format
    /// ```ignore
    /// signature:  `b"\x48\x8B\x05\x00\x00\x00\x00"`
    /// mask:       `"...????"`
    /// ```
    ///
    /// # Good Practices
    /// * In the mask string, use a `[?]` for each wildcard byte, and `[.]` for each non-wildcard byte.
    /// * In the byte array, use `\x00` for each wildcard byte, and the actual byte
    /// value for each non-wildcard byte.<br><br>
    pub fn code_style(&mut self, signature: &[u8], mask: &str) -> Option<&mut Self> {
        let signature_vec: Vec<u8> = signature.to_vec();
        let mask_vec: Vec<bool> = mask.chars().map(|c| c != '?').collect();

        if signature_vec.len() != mask_vec.len() {
            None
        } else {
            self.signature = signature_vec;
            self.mask = mask_vec;
            Some(self)
        }
    }

    /// Initializes the pattern with an IDA-style signature.<br><br>
    ///
    /// An IDA-style signature is characterized by a single string of hexadecimal
    /// values separated by spaces.<br>
    /// In this string, you can use `?` to represent a wildcard byte.<br><br>
    ///
    /// It is generally preferred as it is shorter and easier to read, but it may
    /// introduce some overhead as it is ultimately converted to a code-style like AOB.<br><br>
    ///
    /// # Arguments
    /// * `pattern` - The IDA-style pattern string.
    ///
    /// # Returns
    /// The current instance of the pattern, or `None` if the parameters are invalid.<br><br>
    ///
    /// # Format
    /// ```ignore
    /// pattern:    "48 8B 05 ? ? ? ?"
    /// ```
    pub fn ida_style(&mut self, pattern: &str) -> Option<&mut Self> {
        if pattern.is_empty() {
            return None;
        }

        let mut signature_bytes: Vec<u8> = Vec::new();
        let mut mask_bytes: Vec<bool> = Vec::new();

        pattern.split_whitespace().for_each(|pair| {
            if pair == "?" {
                mask_bytes.push(false);
                signature_bytes.push(0);
            } else {
                mask_bytes.push(true);
                // todo: handle invalid hex values, maybe return a Result instead of an Option?
                signature_bytes.push(
                    u8::from_str_radix(pair, 16).unwrap()
                );
            }
        });

        if signature_bytes.is_empty() {
            return None;
        }

        self.mask = mask_bytes;
        self.signature = signature_bytes;
        Some(self)
    }

    /// Sets the number of threads to use for scanning.<br>
    /// The number of threads is considered invalid if it is set to `0` or greater than
    /// the number of logical CPU cores.<br><br>
    ///
    /// # Arguments
    /// * `threads` - The number of threads to use.
    ///
    /// # Returns
    /// The current instance of the pattern if the number of threads is valid, otherwise `None`.
    pub fn with_threads(&mut self, threads: usize) -> Option<&mut Self> {
        if threads == 0 || threads > num_cpus::get() {
            None
        } else {
            self.threads = threads;
            Some(self)
        }
    }

    /// Sets the number of threads to use for scanning to the number of logical CPU cores.<br><br>
    ///
    /// # Returns
    /// The current instance of the pattern.
    pub fn with_all_threads(&mut self) -> &mut Self {
        self.threads = num_cpus::get();
        self
    }

    /// Internal function that calculates the overlapped
    /// data range between N chunks.<br><br>
    ///
    /// This is used to split the data into chunks to give to each thread.<br><br>
    ///
    /// # Arguments
    /// * `data_size` - The length of the total data.
    /// * `chunks` - The number of chunks to split the data into.
    /// * `overlap` - The number of bytes to overlap between chunks. (at start and end)
    /// * `index` - The index of the chunk to calculate the range for.
    ///
    /// # Returns
    /// A tuple containing the start and end of the chunk.
    fn get_chunk_range(
        data_size: usize,
        chunks: usize,
        overlap: usize,
        index: usize,
    ) -> (usize, usize) {
        let chunk_size = data_size / chunks;
        let remainder = data_size % chunks;

        // Start points to the beginning of the new chunk data.
        let start = index * chunk_size;

        // End points to the end of the new chunk data.
        // If this is the last chunk, add the remainder to the end.
        let end = if index == chunks - 1 {
            start + chunk_size + remainder
        } else {
            start + chunk_size
        };

        // Overlap the chunks by the length of the signature - 1.
        // This is to avoid missing matches that are split between chunks.
        let start = if start >= overlap {
            start - overlap
        } else {
            start
        };

        let end = if end < data_size - overlap {
            end + overlap
        } else {
            end
        };

        (start, end)
    }

    /// Internal function that scans a chunk of data for the pattern.<br><br>
    /// It is executed in parallel by each thread, each with
    /// a different chunk of data.<br><br>
    ///
    /// This function runs until the chunk is fully scanned, the callback returns `false`, or
    /// the atomic finished flag is set to `true`. (meaning that another thread already
    /// received `false` from the callback)<br><br>
    ///
    /// # Arguments
    /// * `data` - The data to scan.
    /// * `signature` - The signature to search for.
    /// * `mask` - The mask to use for the signature.
    /// * `finished` - The atomic flag used to exit the loop early.
    /// * `callback` - The callback to execute when a match is found.
    fn scan_chunk(
        data: &[u8],
        signature: &[u8],
        mask: &[bool],
        finished: &Arc<AtomicBool>,
        callback: Arc<Mutex<impl FnMut(usize) -> bool + Send + Sync>>,
    ) -> bool {
        let signature_len = signature.len();
        let mut found_global = false;

        // idea: Store the first non-wildcard byte in the signature, and only
        // search for that byte first.
        // This could improve performance by quite a bit.

        // Iterate over the chunk data.
        for i in 0..data.len() - signature_len {
            let mut found = true;

            // If the running flag is set to false, stop the scan.
            // This is used to stop all threads if a match is found.
            if finished.load(Ordering::SeqCst) {
                return found_global;
            }

            // Iterate and compare the signature bytes.
            for j in 0..signature_len {
                if data[i + j] != signature[j] && mask[j] == true {
                    // Break out of the loop if a byte doesn't match.
                    found = false;
                    break;
                }
            }

            if found {
                // Acquire the mutex and run the scan callback function.
                // We need to lock the mutex to prevent multiple threads from
                // running the callback at the same time.
                // This should not impact performance too much, as the callback
                // is only executed when a match is found.
                if !callback.lock().unwrap().deref_mut()(i) {
                    // If the callback returns false, stop scanning bet.
                    finished.store(true, Ordering::SeqCst);
                    return true;
                } else {
                    found_global = true;
                }
            }
        }

        found_global
    }

    /// Performs the AOB scan in the given slice.<br><br>
    ///
    /// If specified, this function will split the data into chunks and scan
    /// each chunk in parallel.<br><br>
    ///
    /// # Arguments
    /// * `data` - The data slice to scan.
    /// * `callback` - The callback to execute when a match is found.
    ///    - The callback receives the offset of the match as an argument.
    ///    - It should return `true` to continue scanning, or `false` to stop.
    ///
    /// # Returns
    /// True if at least one match was found, otherwise false.
    pub fn scan(
        &mut self,
        data: &[u8],
        callback: impl FnMut(usize) -> bool + Send + Sync,
    ) -> bool {
        // Count the number of running threads, so we can wait for them to finish.
        let running_threads = Arc::new(AtomicUsize::new(0));
        // Atomic flag to stop all threads if a match is found and accepted.
        let finished = Arc::new(AtomicBool::new(false));
        // Atomic flag to check if any threads found a match.
        let found = Arc::new(AtomicBool::new(false));
        // Mutex for the callback function.
        let callback_arc = Arc::new(Mutex::new(callback));

        // Using a thread scope allows us to pass non 'static references to the threads.
        std::thread::scope(|scope| {
            // Iterate over the number of threads to spawn.
            for tc in 0..self.threads {
                // Split the data into an overlapped chunks.
                // Each thread will scan a chunk of the data.
                let range = Self::get_chunk_range(
                    data.len(),
                    // Create a chunk for each thread.
                    self.threads,
                    // Overlap the chunks by the length of the signature - 1, to avoid missing
                    // matches that are split between chunks.
                    self.signature.len() - 1,
                    tc,
                );

                // Copy the signature and mask to the thread.
                let signature = self.signature.clone();
                let mask = self.mask.clone();

                // Clone the atomic flags and callback function.
                let running_threads = running_threads.clone();
                let finished = finished.clone();
                let found = found.clone();
                let callback = callback_arc.clone();

                // Spawn a new worker thread and increment the atomic running thread count.
                running_threads.fetch_add(1, Ordering::SeqCst);
                scope.spawn(move || {
                    // Resize the slice to the chunk region.
                    let data = &data[range.0..range.1];

                    // Scan the chunk of data.
                    if Self::scan_chunk(
                        data,
                        &signature,
                        &mask,
                        &finished,
                        callback,
                    ) {
                        // If a match was found, set the found flag to true.
                        found.store(true, Ordering::SeqCst);
                    }

                    // Thread has finished, decrement the atomic running thread count.
                    running_threads.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        // Spin wait until all threads have finished.
        while running_threads.load(Ordering::SeqCst) != 0 {
            std::thread::sleep(Duration::from_millis(1));
        }

        // Return true if at least one match was found.
        found.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;

    //noinspection ALL
    fn random_bytes(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

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
        let mut result = Pattern::new()
            .ida_style("55 48 89 E5 ? 8B ? ? 00 ? ? 8B ? ? 5D C3")
            .unwrap()
            .with_all_threads()
            .scan(&random_bytes, |offset| {
                if offset as isize == target_offset { correct = true; }
                true
            });

        assert!(correct);
        assert!(result);

        // Run the code-style AOB scan.
        correct = false;
        result = Pattern::new()
            .code_style(
                b"\x55\x48\x89\xE5\x00\x8B\x00\x00\x00\x00\x00\x8B\x00\x00\x5D\xC3",
                "....?.??.??.??..",
            )
            .unwrap()
            .with_all_threads()
            .scan(&random_bytes, |offset| {
                if offset as isize == target_offset { correct = true; }
                true
            });

        assert!(correct);
        assert!(result);
    }

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
        let result = Pattern::new()
            .ida_style("55 48 89 E5 48 8B")
            .unwrap()
            .with_all_threads()
            .scan(&random_bytes, |offset| {
                if offset as isize == target_offset { correct = true; }
                true
            });

        assert!(correct);
        assert!(result);
    }

    #[test]
    /// Test that the scanner can properly notify the caller when no matches are found.
    fn scan_no_matches() {
        // Create an empty data buffer.
        let random_bytes = [0u8; 1024 * 1024 /* 1 MB */];

        // Match all the bytes.
        // This data does not exist in the data buffer, so no matches should be found.
        let mut called = false;
        let result = Pattern::new()
            .ida_style("55 48 89 E5 ? 8C")
            .unwrap()
            .with_all_threads()
            .scan(&random_bytes, |offset| {
                println!("Found match at offset 0x{:X}", offset);
                called = true;
                true
            });

        assert!(!called);
        assert!(!result);
    }
}
