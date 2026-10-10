//! NexusBackup plugin `truenas` (docs/truenas-connector.md §9).

fn main() {
    plugin_sdk::run(truenas_plugin::TrueNasPlugin {
        connect: truenas_plugin::Real,
    })
}
