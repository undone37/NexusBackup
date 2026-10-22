//! Offsite tier (plan §9): encrypted pack files on a dumb remote (Hetzner Storage Box, S3).

pub mod cfg;
pub mod config;
pub mod dr;
pub mod pack;
pub use ::remote::{remote, s3, sftp, xml};
pub mod target;
