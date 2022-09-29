use super::Pattern;

/// An error in the pattern builder.<br>
/// This encapsulates all possible errors that can occur when building a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// Thrown when the signature's byte parsing fails.
    ParseError(std::num::ParseIntError),
    /// Thrown when the size of the signature differs from the size of the mask.
    SizeMismatch,
    /// Thrown when the signature is empty.
    InvalidSignature,
    /// Thrown when the selected worker threads count is invalid.
    InvalidThreadCount,
}

impl std::fmt::Display for BuilderError {
    /// Formats the various errors that can occur when building a pattern.<br><br>
    ///
    /// # Arguments
    /// * `f` - The formatter.
    ///
    /// # Returns
    /// Whether the formatting was successful or not.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(err) => write!(f, "{}", err),
            Self::SizeMismatch => write!(f, "the size of signature and mask do not match"),
            Self::InvalidSignature => write!(f, "the signature is not formatted correctly"),
            Self::InvalidThreadCount => write!(f, "the thread count must be greater than zero and less than or equal to the number of logical cores"),
        }
    }
}

impl std::error::Error for BuilderError {}

impl From<std::num::ParseIntError> for BuilderError {
    /// Converts a `ParseIntError` into a `BuilderError`.<br><br>
    ///
    /// # Arguments
    /// * `err` - The error to convert.
    ///
    /// # Returns
    /// The converted error.
    fn from(err: std::num::ParseIntError) -> Self {
        Self::ParseError(err)
    }
}

/// Builder for the Pattern struct.<br>
/// The builder is used to create a Pattern struct with the desired settings.<br><br>
///
/// # Examples
///
/// ## Multi-threaded scan for an IDA-style pattern
/// ```
/// let data = std::fs::read("some.bin").unwrap();
/// let found = aobscan::PatternBuilder::new()
///     .ida_style("48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ?")
///     .unwrap()
///     .with_all_threads()
///     .build()
///     .scan(&data, move |offset| {
///         println!("Match at offset {:#02x}", offset);
///         true // Return true to continue scanning for other matches
///     });
/// ```
///
/// ## Single-threaded scan for a code-style pattern
/// ```
/// let data = std::fs::read("some.bin").unwrap();
/// let found = aobscan::PatternBuilder::new()
///     .code_style(b"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00", "...????...????")
///     .unwrap()
///     .with_threads(1)
///     .unwrap()
///     .build()
///     .scan(&data, move |offset| {
///         println!("Match at offset {:#02x}", offset);
///         true // Return true to continue scanning for other matches
///     });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternBuilder {
    signature: Vec<u8>,
    mask: Vec<bool>,
    threads: usize,
}

impl PatternBuilder {
    /// Creates an empty pattern builder.
    pub fn new() -> Self {
        Self {
            threads: 1,
            signature: vec![],
            mask: vec![],
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
    /// # Good Practices
    /// * In the mask string, use a `[?]` for each wildcard byte, and `[.]` for each non-wildcard byte.
    /// * In the byte array, use `\x00` for each wildcard byte, and the actual byte
    /// value for each non-wildcard byte.
    ///
    /// # Format
    /// ```ignore
    /// signature:  `b"\x48\x8B\x05\x00\x00\x00\x00"`
    /// mask:       `"...????"`
    /// ```
    pub fn code_style(mut self, signature: &[u8], mask: &str) -> Result<Self, BuilderError> {
        let signature_vec: Vec<u8> = signature.to_vec();
        let mask_vec: Vec<bool> = mask.chars().map(|c| c != '?').collect();

        if signature_vec.len() != mask_vec.len() {
            Err(BuilderError::SizeMismatch)
        } else {
            self.signature = signature_vec;
            self.mask = mask_vec;
            Ok(self)
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
    /// The current instance of the builder, or `None` if the parameters are invalid.<br><br>
    ///
    /// # Format
    /// ```ignore
    /// pattern:    "48 8B 05 ? ? ? ?"
    /// ```
    pub fn ida_style(mut self, pattern: &str) -> Result<Self, BuilderError> {
        if pattern.is_empty() {
            return Err(BuilderError::InvalidSignature);
        }

        let mut signature_bytes: Vec<u8> = vec![];
        let mut mask_bytes: Vec<bool> = vec![];

        for pair in pattern.split_whitespace() {
            if pair == "?" {
                mask_bytes.push(false);
                signature_bytes.push(0);
            } else {
                mask_bytes.push(true);
                signature_bytes.push(
                    u8::from_str_radix(pair, 16)?
                );
            }
        }

        if signature_bytes.is_empty() {
            return Err(BuilderError::InvalidSignature);
        }

        self.mask = mask_bytes;
        self.signature = signature_bytes;
        Ok(self)
    }

    /// Sets the number of threads to use for scanning.<br>
    /// The number of threads is considered invalid if it is set to `0` or greater than
    /// the number of logical CPU cores.<br><br>
    ///
    /// # Arguments
    /// * `threads` - The number of threads to use.
    ///
    /// # Returns
    /// The current instance of the builder if the number of threads is valid, otherwise `None`.
    pub fn with_threads(mut self, threads: usize) -> Result<Self, BuilderError> {
        if threads == 0 || threads > num_cpus::get() {
            Err(BuilderError::InvalidThreadCount)
        } else {
            self.threads = threads;
            Ok(self)
        }
    }

    /// Sets the number of threads to use for scanning to the number of logical CPU cores.<br><br>
    ///
    /// # Returns
    /// The current instance of the builder.
    pub fn with_all_threads(mut self) -> Self {
        self.threads = num_cpus::get();
        self
    }

    /// Builds a new pattern instance with the specified settings.<br><br>
    ///
    /// # Returns
    /// The created pattern instance.
    pub fn build(self) -> Pattern {
        Pattern {
            signature: self.signature,
            mask: self.mask,
            threads: self.threads,
        }
    }
}
