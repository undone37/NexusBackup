//! NexusBackup plugin `nexusstor` (docs/nexusstor-design.md).

fn main() {
    plugin_sdk::run(nexusstor_plugin::NexusStorPlugin)
}
