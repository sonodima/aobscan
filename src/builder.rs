use super::Pattern;

/// An error in the pattern builder.<br>
/// This encapsulates all possible errors that can occur when building a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// Thrown when the signature's byte parsing fails.
    ParseError(std::num::ParseIntError),
    /// Thrown when the size of the signature differs from the size of the mask.
    SizeMismatch,
    /// Thrown when the signature is empty or invalid.
    InvalidSignature(String),
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
            Self::InvalidSignature(message) => write!(f, "{}", message),
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
/// let found = aobscan::PatternBuilder::from_ida_style("48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ?")
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
/// let found = aobscan::PatternBuilder::from_code_style(
///     b"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00",
///     "...????...????"
/// ).unwrap()
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
    /// Creates a pattern builder from a code-style signature.<br><br>
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
    /// This pattern representation is usually the most safe and reliable, but it is also
    /// the most verbose and tedious to write.<br><br>
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
    /// # Errors
    /// * `BuilderError::SizeMismatch` - The size of the signature and mask do not match.
    ///
    /// # Format
    /// ```ignore
    /// signature:  `b"\x48\x8B\x05\x00\x00\x00\x00"`
    /// mask:       `"...????"`
    /// ```
    pub fn from_code_style(signature: &[u8], mask: &str) -> Result<Self, BuilderError> {
        let signature_bytes: Vec<u8> = signature.to_vec();
        let mask_bytes: Vec<bool> = mask.chars().map(|c| c != '?').collect();

        if signature_bytes.len() != mask_bytes.len() {
            Err(BuilderError::SizeMismatch)
        } else {
            Ok(Self {
                signature: signature_bytes,
                mask: mask_bytes,
                threads: 1,
            })
        }
    }

    /// Creates a pattern builder from an IDA-style signature.<br><br>
    ///
    /// An IDA-style signature is characterized by a single string of hexadecimal
    /// values separated by spaces.<br>
    /// In this string, you can use `?` or `??` to represent a wildcard byte.<br><br>
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
    /// # Errors
    /// * `BuilderError::InvalidSignature` - The pattern string is empty.
    /// * `BuilderError::ParseError` - The pattern string contains invalid hexadecimal values.
    ///
    /// # Format
    /// ```ignore
    /// pattern:    "48 8B 05 ? ? ? ?" // or "48 8B 05 ?? ?? ?? ??"
    /// ```
    pub fn from_ida_style(pattern: &str) -> Result<Self, BuilderError> {
        if pattern.is_empty() {
            Err(BuilderError::InvalidSignature(
                "the pattern cannot be empty".to_string()
            ))?
        }

        let mut signature_bytes: Vec<u8> = vec![];
        let mut mask_bytes: Vec<bool> = vec![];

        for pair in pattern.split_whitespace() {
            if pair == "?" || pair == "??" {
                mask_bytes.push(false);
                signature_bytes.push(0);
            } else {
                mask_bytes.push(true);
                signature_bytes.push(
                    u8::from_str_radix(pair, 16)?
                );
            }
        }

        Ok(Self {
            signature: signature_bytes,
            mask: mask_bytes,
            threads: 1,
        })
    }

    /// Creates a pattern builder from a string of non-spaced, case-insensitive hex bytes.<br><br>
    ///
    /// The string must contain only hexadecimal characters (or '??'s for wildcard bytes),
    /// and its length must be a multiple of 2.<br>
    /// Single-char wildcards are not supported!<br><br>
    ///
    /// # Arguments
    /// * `pattern` - The pattern string.
    ///
    /// # Returns
    /// The current instance of the builder, or `None` if the parameter is invalid.<br><br>
    ///
    /// # Errors
    /// * `BuilderError::InvalidSignature` - The pattern is empty, its length is odd, contains invalid characters or single-char wildcards.
    /// * `BuilderError::ParseError` - The pattern contains invalid hexadecimal characters.
    ///
    /// # Format
    /// ```ignore
    /// pattern:    "488b05????????488b88??" // a pair of '??'s represents a wildcard byte
    /// ```
    pub fn from_hex_string(pattern: &str) -> Result<Self, BuilderError> {
        if pattern.is_empty() {
            Err(BuilderError::InvalidSignature(
                "the pattern cannot be empty".to_string()
            ))?
        }

        // A hex string must have an even number of characters.
        if pattern.len() % 2 != 0 {
            Err(BuilderError::InvalidSignature(
                "the pattern must have an even number of characters".to_string()
            ))?
        }

        let mut signature_bytes: Vec<u8> = vec![];
        let mut mask_bytes: Vec<bool> = vec![];

        for pair in pattern.as_bytes().chunks(2) {
            if pair == b"??" {
                mask_bytes.push(false);
                signature_bytes.push(0);
            } else if pair.contains(&b'?') {
                // If the pair contains a single '?', it is invalid.
                // At the moment, the library doesn't support single '?' wildcards.
                Err(BuilderError::InvalidSignature(
                    "the pattern does not accept single '?' wildcards".to_string()
                ))?
            } else {
                mask_bytes.push(true);
                match std::str::from_utf8(pair) {
                    Ok(pair) => {
                        signature_bytes.push(
                            u8::from_str_radix(pair, 16)?
                        );
                    }
                    Err(_) => Err(BuilderError::InvalidSignature(
                        "the pattern contains an invalid character".to_string()
                    ))?
                }
            }
        }

        Ok(Self {
            signature: signature_bytes,
            mask: mask_bytes,
            threads: 1,
        })
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
        Pattern::new(self.signature, self.mask, self.threads)
    }
}
