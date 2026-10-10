//! Offsite tier (plan §9): encrypted pack files on a dumb remote (Hetzner Storage Box, S3).

pub mod pack;
pub mod remote;
pub mod s3;
pub mod sftp;
pub mod target;
pub mod xml;
