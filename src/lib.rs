pub use builder::{BuilderError, PatternBuilder};
#[cfg(feature = "object-scan")]
pub use object_scan::{ObjectError, ObjectScan, SectionResult};
pub use pattern::Pattern;

mod builder;
#[cfg(feature = "object-scan")]
mod object_scan;
mod pattern;
