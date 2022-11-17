use object::{
    macho::FatHeader,
    Object,
    ObjectSection,
    read::macho::FatArch,
    Section,
};

use crate::Pattern;

/// Information about a match found by the scanner in a section of an object file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionResult {
    /// The offset of the match in the raw data slice. (archive offset + section offset)
    pub raw_offset: usize,

    /// The offset of the match in the specified section. (section address + match offset)
    pub section_offset: usize,

    /// The base address of the specified section.
    pub section_address: u64,

    /// An identifier for the archive containing the value.<br><br>
    ///
    /// # Values
    /// - `None` if the value is not contained in an archive.
    /// - `Some(architecture)` if the value is contained a Mach-O archive.
    pub archive_id: Option<String>,
}


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


/// Implements object file scanning for the pattern.
///
/// This is useful for restricting the scan to a specific section of
/// a binary file, such as the `__text` section.<br>
/// This reduces the amount of data that needs to be scanned, and can
/// drastically improve the scan speed.<br><br>
pub trait ObjectScan {
    /// Performs the AOB scan in the specified object section of the given slice.<br><br>
    ///
    /// If the section is not found, the scan is not performed, and `false` is returned.<br><br>
    ///
    /// FAT Mach-O binaries are also supported, and in this case all the THIN binaries
    /// are scanned for the given section.<br>
    /// Information about which THIN binary contains the match is returned in
    /// the callback.<br><br>
    ///
    /// # Arguments
    /// * `data` - The data slice to scan.
    /// * `section_name` - The name of the section to scan. (e.g. `__text`)
    /// * `callback` - The callback to execute when a match is found.
    ///    - The callback receives a structure containing all the information of the match as argument.
    ///    - It should return `true` to continue scanning, or `false` to stop.
    ///
    /// # Returns
    /// Ok(true) if at least one match was found, Ok(false) if no matches were found,
    /// Err if an error occurred.
    fn scan_object(
        &self,
        data: &[u8],
        section_name: &str,
        callback: impl FnMut(SectionResult) -> bool + Send + Sync,
    ) -> Result<bool, ObjectError>;
}

impl ObjectScan for Pattern {
    fn scan_object(
        &self,
        data: &[u8],
        section_name: &str,
        mut callback: impl FnMut(SectionResult) -> bool + Send + Sync,
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
            scan_section(&self, &section, None, 0, &mut callback)
        }
        // Mach-O FAT archives.
        else if let Ok(archive) = FatHeader::parse_arch32(&*data) {
            let mut section_found = false;
            let mut found = false;

            // Iterate over the THIN binaries in the FAT file.
            for arch in archive {
                // Get the data slice of the THIN binary.
                if let Ok(data) = arch.data(&*data) {
                    // Parse the object file.
                    let file = object::File::parse(data)
                        .or(Err(ObjectError::InvalidObject))?;

                    // Find the section with the specified name.
                    if let Some(section) = file.section_by_name(section_name) {
                        section_found = true;

                        // Perform the scan in the section.
                        if scan_section(
                            &self,
                            &section,
                            Some(format!("{:#?}", arch.architecture())),
                            arch.offset() as usize,
                            &mut callback,
                        )? {
                            found = true;
                        }
                    }
                }
            }

            if !section_found {
                // If the section was not found in any of the THIN binaries, return an error.
                Err(ObjectError::SectionNotFound)
            } else {
                // Return true if at least one match was found.
                Ok(found)
            }
        }
        // Invalid binary file format.
        else {
            Err(ObjectError::InvalidObject)
        }
    }
}


/// Internal function that scans a binary section for a pattern.<br>
/// This function is used by both normal and FAT Mach-O binaries, and it
/// is a wrapper around the normal Pattern::scan function.<br><br>
///
/// The callback is also wrapped to add other useful information to its
/// arguments.<br><br>
///
/// # Arguments
/// * `section` - The section to scan.
/// * `archive_id` - An identifier for the archive that contains the section. (passed to the callback)
///   - Normal binaries should pass `None`.
/// * `archive_offset` - The offset to the archive that contains the section. (used to calculate the absolute offset)
/// * `callback` - The callback to execute when a match is found.
///
/// # Returns
/// Ok(true) if at least one match was found, Ok(false) if no matches were found,
/// Err if an error occurred.
fn scan_section(
    pattern: &Pattern,
    section: &Section,
    archive_id: Option<String>,
    archive_offset: usize,
    callback: &mut (impl FnMut(SectionResult) -> bool + Send + Sync),
) -> Result<bool, ObjectError> {
    // Get the data slice of the section.
    // This is the same as creating another slice from the data slice,
    // using the section's offset and size.
    let section_data = section.data()
        .or(Err(ObjectError::SectionDataNotFound))?;

    // Get the raw file offset of the section. (archive offset + section offset)
    // In THIN binaries, the archive offset is 0.
    let section_base = archive_offset + section.file_range()
        .ok_or(ObjectError::SectionDataNotFound)?.0 as usize;

    // Wrap the callback function to add another argument to it.
    // This allows us to pass both the section and file offset to the callback.
    Ok(pattern.scan(section_data, |offset| {
        // Call the callback function with all the relevant data.
        callback(SectionResult {
            raw_offset: section_base + offset,
            section_offset: offset,
            section_address: section.address(),
            archive_id: archive_id.clone(),
        })
    }))
}
