use std::fmt::{Display, Formatter};
use std::ops::DerefMut;
use std::sync::{
    Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, Mutex,
};
use std::time::Duration;

/// A pattern that can be used to scan for matches in a byte array.<br><br>
///
/// This is the main type of this crate, and you can create it
/// using the [`PatternBuilder`](struct.PatternBuilder.html) struct.<br><br>
///
/// Internally, a pattern is represented as a vector of bytes for the signature,
/// a vector of booleans for the mask, and the number of threads to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub(crate) signature: Vec<u8>,
    pub(crate) mask: Vec<bool>,
    pub(crate) threads: usize,
}

impl Pattern {
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
    /// * `chunk_offset` - Starting offset of the chunk, used to calculate the absolute match address.
    /// * `finished` - The atomic flag used to exit the loop early.
    /// * `callback` - The callback to execute when a match is found.
    ///
    /// # Returns
    /// True if at least one match was found, false otherwise (or if the routine
    /// finished early due to the `finished` flag).
    fn scan_chunk(
        data: &[u8],
        signature: &[u8],
        mask: &[bool],
        chunk_offset: usize,
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
                if !callback.lock().unwrap().deref_mut()(chunk_offset + i) {
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
        &self,
        data: &[u8],
        callback: impl FnMut(usize) -> bool + Send + Sync,
    ) -> bool {
        // Atomic flag to stop all threads if a match is found and accepted.
        let finished = Arc::new(AtomicBool::new(false));
        // Mutex for the callback function.
        let callback_arc = Arc::new(Mutex::new(callback));

        if self.threads > 1 {
            // If the scan is multi-threaded, split the data into chunks and
            // scan each chunk in parallel.

            // Count the number of running threads, so we can wait for them to finish.
            let running_threads = Arc::new(AtomicUsize::new(0));
            // Atomic flag to check if any threads found a match.
            let found = Arc::new(AtomicBool::new(false));

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
                            range.0,
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
        } else {
            // If the scan is single-threaded, avoid the threading clutter and
            // simply scan the data in the current thread.
            Self::scan_chunk(
                data,
                &self.signature,
                &self.mask,
                0,
                &finished,
                callback_arc,
            )
        }
    }
}

impl Display for Pattern {
    /// Formats the pattern as a string of hexadecimal bytes (or '?') separated by spaces.<br><br>
    ///
    /// # Arguments
    /// * `f` - The formatter.
    ///
    /// # Returns
    /// Whether the formatting was successful or not.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ ")?;
        for (i, byte) in self.signature.iter().enumerate() {
            if self.mask[i] {
                write!(f, "{:02X} ", byte)?;
            } else {
                write!(f, "? ")?;
            }
        }
        write!(f, "] [t={}]", self.threads)
    }
}
