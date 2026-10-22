//! Storage backends of offsite copies (Phase 4/8): a local directory, SFTP and S3 (with Object Lock), behind
//! [`Remote`]. A crate of their own (Phase 38c) so standalone agents can use them without the appliance's key
//! service and catalog; `offsite` re-exports them.

mod lib_remote;
pub mod s3;
pub mod sftp;
pub mod xml;

pub use lib_remote::*;
/// The trait module under its old name (`remote::remote::Remote` in older code paths).
pub mod remote {
    pub use crate::lib_remote::*;
}
