//! nexus-index (Phase 31b, docs/file-index-v2-plan.md): the instant file
//! search. One embedded Tantivy index per tenant whose files are sealed with
//! the tenant keyring ([`sealdir`]); documents are file versions ([`model`])
//! built from the sealed per-snapshot name indexes, which stay the source of
//! truth; include/exclude rules per source ([`rules`]); queries, grouping and
//! paging ([`query`]); the service with its sync loop ([`service`]). The
//! protocol lives in the crate index-proto.

pub mod model;
pub mod query;
pub mod rules;
pub mod sealdir;
pub mod service;
