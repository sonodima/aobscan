use std::ops::DerefMut;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};

use object::{Architecture, Object, ObjectSection, Section};
use object::macho::FatHeader;
use object::read::archive::ArchiveFile;
use object::read::macho::FatArch;

/// An error in the object pattern scanner.<br>
/// This encapsulates all possible errors that can occur when scanning for
/// a pattern in an object file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    /// Thrown when the content of the data to scan is not a valid object file.
    InvalidObject,
    /// Thrown when the the specified binary section to scan for the pattern is not found.
    SectionNotFound,
    /// Thrown when the data of the specified binary section is not available.
    SectionDataNotFound,
}

impl std::fmt::Display for ObjectError {
    /// Formats the various errors that can occur when scanning for a pattern
    /// in an object file.<br><br>
    ///
    /// # Arguments
    /// * `f` - The formatter.
    ///
    /// # Returns
    /// Whether the formatting was successful or not.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidObject => write!(f, "the content of the data to scan is not a valid object file"),
            Self::SectionNotFound => write!(f, "the specified binary section is not found"),
            Self::SectionDataNotFound => write!(f, "the data of the specified binary section is not available"),
        }
    }
}

impl std::error::Error for ObjectError {}

/// A pattern that can be used to scan for matches in a byte array.<br><br>
///
/// This is the main type of this crate, and you can create it
/// using the [`PatternBuilder`](struct.PatternBuilder.html) struct.<br><br>
///
/// Internally, a pattern is represented as a vector of bytes for the signature,
/// a vector of booleans for the mask, and the number of threads to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    signature: Vec<u8>,
    mask: Vec<bool>,
    threads: usize,
    start_offset: usize,
}

impl Pattern {
    /// Creates a new pattern from the given signature, mask and threads number.<br><br>
    ///
    /// # Arguments
    /// * `signature` - The signature to scan for.
    /// * `mask` - The mask in which the wildcard bytes are represented by `false`.
    /// * `threads` - The number of threads to use.
    ///
    /// # Returns
    /// The newly created pattern.
    pub fn new(mut signature: Vec<u8>, mut mask: Vec<bool>, threads: usize) -> Self {
        // Optimize the pattern by removing the trailing wildcards.
        //
        // Example:
        // - Input:         [? ? 48 8B ? 00 ? ? ?]
        // - Optimized:     [48 8B ? 00]
        //
        // This is done by calculating the actual offsets from the beginning and
        // end of the pattern, and then slicing the vectors to only keep the
        // relevant bytes.
        let mut start_offset = mask.iter().take_while(|&&x| x == false).count();
        let end_offset = mask.iter().rev().take_while(|&&x| x == false).count();

        // Only resize the vectors if there is at least one non-wildcard byte.
        // I have no idea why anyone would want to scan for a pattern that is
        // entirely made of wildcards, but hey, it's their choice.
        if start_offset != mask.len() {
            signature = signature[start_offset..signature.len() - end_offset].to_vec();
            mask = mask[start_offset..mask.len() - end_offset].to_vec();
        } else {
            // If the pattern does not have any non-wildcard bytes, we can ignore the offsets.
            start_offset = 0;
        }

        Self {
            signature,
            mask,
            threads,
            start_offset,
        }
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
                        if self.scan_chunk(
                            data,
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
                std::thread::sleep(std::time::Duration::from_millis(1));
            }

            // Return true if at least one match was found.
            found.load(Ordering::SeqCst)
        } else {
            // If the scan is single-threaded, avoid the threading clutter and
            // simply scan the data in the current thread.
            self.scan_chunk(
                data,
                0,
                &finished,
                callback_arc,
            )
        }
    }

    fn scan_section(
        &self,
        section: &Section,
        callback: &mut (impl FnMut(usize, usize) -> bool + Send + Sync),
        archive_id: Option<&str>,
    ) -> Result<bool, ObjectError> {
        // Get the data slice of the section.
        // This is the same as creating another slice from the data slice,
        // using the section's offset and size.
        let section_data = section.data()
            .or(Err(ObjectError::SectionDataNotFound))?;

        // Get the raw file offset of the section.
        let section_offset = section.file_range()
            .ok_or(ObjectError::SectionDataNotFound)?.0 as usize;

        // Wrap the callback function to add another argument to it.
        // This allows us to pass both the section and file offset to the callback.
        Ok(self.scan(section_data, |offset| {
            println!("<< {:?} >>", archive_id);
            callback(section_offset + offset, offset)
        }))
    }

    /// Performs the AOB scan in the specified object section of the given slice.<br><br>
    ///
    /// This function is useful for restricting the scan to a specific section of
    /// a binary file, such as the `__text` section.<br>
    /// This reduces the amount of data that needs to be scanned, and can
    /// drastically improve the scan speed.<br><br>
    ///
    /// If the section is not found, the scan is not performed, and `false` is returned.<br><br>
    ///
    /// The implementation of the scan algorithm is the same as the one of
    /// the `scan` function.<br><br>
    ///
    /// # Arguments
    /// * `data` - The data slice to scan.
    /// * `section_name` - The name of the section to scan. (e.g. `__text`)
    /// * `callback` - The callback to execute when a match is found.
    ///    - The callback receives the data_offset and section_offset of the match as arguments.
    ///    - It should return `true` to continue scanning, or `false` to stop.
    ///
    /// # Returns
    /// True if at least one match was found, otherwise false.
    pub fn scan_object(
        &self,
        data: &[u8],
        section_name: &str,
        mut callback: impl FnMut(usize, usize) -> bool + Send + Sync,
    ) -> Result<bool, ObjectError> {
        // Different object file formats must be handled individually.
        // For instance, Mach-O FAT files contain multiple architecture binaries,
        // and we must scan the section in each one of them.

        // Normal binary files only containing one architecture.
        if let Ok(file) = object::File::parse(data) {
            // Find the section with the specified name. (name is case-sensitive)
            let section = file.section_by_name(section_name)
                .ok_or(ObjectError::SectionNotFound)?;

            // Perform the scan in the section.
            self.scan_section(&section, &mut callback, None)
        }
        // Mach-O 32-bit FAT files.
        else if let Ok(archive) = FatHeader::parse_arch32(&*data) {
            // Iterate over the THIN binaries in the FAT file.
            for arch in archive {
                // Parse the object file.
                let file = object::File::parse(
                    arch.data(&*data).unwrap()
                ).unwrap();

                // Find the section with the specified name.
                let section = file.section_by_name(section_name)
                    .ok_or(ObjectError::SectionNotFound)?;

                // Perform the scan in the section.
                self.scan_section(
                    &section,
                    &mut callback,
                    Some(&format!("{:#?}", arch.architecture())),
                )?;
            }

            Ok(false)
        }
        // Mach-O 64-bit FAT files.
        else if let Ok(archive) = FatHeader::parse_arch64(&*data) {
            for arch in archive {
                println!("Arch: {:#?}", arch.architecture());

                let file = object::File::parse(
                    arch.data(&*data).unwrap()
                ).unwrap();

                // todo: scan here
            }

            Ok(false)
        }
        // Partially parsed archive files.
        else if let Ok(archive) = ArchiveFile::parse(&*data) {
            println!("Archive File");
            for member in archive.members() {
                let member = member.unwrap();
                println!("Member: {:#?}", member.name());

                let file = object::File::parse(
                    member.data(&*data).unwrap()
                ).unwrap();

                println!("Arch: {:?}", file.architecture());
                // todo: scan here
            }

            Ok(false)
        }
        // Invalid binary file format.
        else {
            Err(ObjectError::InvalidObject)
        }
    }

    /// # Returns
    /// The number of threads to use in scans of this pattern.
    pub fn get_threads(&self) -> usize {
        self.threads
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
        let mut end = start + chunk_size + if index == chunks - 1 { remainder } else { 0 };

        // Overlap the chunks by the length of the signature - 1.
        // This is to avoid missing matches that are split between chunks.
        let start = start - if start >= overlap { overlap } else { 0 };

        // If this is the last chunk, don't overlap the end.
        end = end + if end < data_size - overlap { overlap } else { 0 };

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
    /// * `chunk_offset` - Starting offset of the chunk, used to calculate the absolute match address.
    /// * `finished` - The atomic flag used to exit the loop early.
    /// * `callback` - The callback to execute when a match is found.
    ///
    /// # Returns
    /// True if at least one match was found, false otherwise (or if the routine
    /// finished early due to the `finished` flag).
    fn scan_chunk(
        &self,
        data: &[u8],
        chunk_offset: usize,
        finished: &Arc<AtomicBool>,
        callback: Arc<Mutex<impl FnMut(usize) -> bool + Send + Sync>>,
    ) -> bool {
        // Size of the scan to perform.
        let length = data.len() - self.signature.len();

        // Store the first byte of the signature to compare it with the data.
        // This byte is always not masked due to the optimizations in the pattern
        // creation function, so we can use it to speed up the search.
        let first_byte = self.signature[0];
        let first_mask = self.mask[0];

        // Result of the scan function.
        // This is only relative to this chunk, and is used to determine
        // if at least one match was found in the current function.
        let mut found = false;

        // Iterate over all the scan data.
        for i in 0..length {
            // If the running flag is set to false, stop the scan.
            // This is used to stop all threads if a match is found.
            if finished.load(Ordering::Relaxed) {
                return found;
            }

            // If the first byte matches, compare the rest of the signature,
            // otherwise directly skip to the next byte.
            //
            // We also check for the first mask so that in the case of a pattern
            // with all wildcards, we don't skip the first byte.
            // If the pattern contains at least one non-wildcard byte, the first
            // byte will never be masked.
            if data[i] != first_byte && first_mask {
                continue;
            }

            if self.compare_byte_array(&data[i..]) {
                // Acquire the mutex and run the scan callback function.
                // We need to lock the mutex to prevent multiple threads from
                // running the callback at the same time.
                // This should not impact performance too much, as the callback
                // is only executed when a match is found.
                found = true;
                if !callback.lock().unwrap().deref_mut()(chunk_offset + i - self.start_offset) {
                    // If the callback returns false, stop scanning bet.
                    finished.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }

        found
    }

    /// Internal function that scans for the pattern in a chunk of data.<br><br>
    ///
    /// # Arguments
    /// * `data` - The data to scan for the pattern.
    ///
    /// # Returns
    /// True if the pattern was found in the data, false otherwise.
    fn compare_byte_array(&self, data: &[u8]) -> bool {
        for (i, sig) in self.signature.iter().enumerate() {
            // If the mask is false, it means that the byte is a wildcard.
            // We can skip it.
            if !self.mask[i] {
                continue;
            }

            // If the byte does not match the signature, return false.
            if data[i] != *sig {
                return false;
            }
        }

        // If we reach this point, it means that the byte array matches the signature.
        true
    }
}

impl std::fmt::Display for Pattern {
    /// Formats the pattern as a string of hexadecimal bytes (or '?') separated by spaces.<br><br>
    ///
    /// # Arguments
    /// * `f` - The formatter.
    ///
    /// # Returns
    /// Whether the formatting was successful or not.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
