//! The tests' Microsoft Graph mock as a standalone server with a small demo tenant,
//! for developing against the plugin (and the appliance UI) without a real tenant:
//!
//! ```sh
//! cargo run -p m365-plugin --example graph_mock > /tmp/m365-source.json
//! ```
//!
//! prints the source config (all endpoints → the mock, its CA, the test certificate)
//! and serves until killed. Test-only key material: never use it anywhere else.

#[path = "../tests/mock/mod.rs"]
mod mock;

fn main() {
    let m = mock::Mock::start();
    {
        let mut t = m.lock();
        let alice = t.add_user("Alice", true, true);
        let inbox = t.add_folder(&alice, None, "Inbox");
        t.add_message(&alice, &inbox, "Welcome", "Hello from the Graph mock");
        t.add_event(&alice, "Planning");
        t.add_contact(&alice, None, "Bob Builder");
        let d = t.user_drive(&alice);
        let root = t.drive_root(&d);
        t.add_item(&d, &root, "hello.txt", Some(b"hello".to_vec()));
        t.add_user("Bob", true, true);
        let site = t.add_site("Marketing", &["Documents"]);
        let sd = t.site(&site).drives[0].clone();
        let sr = t.drive_root(&sd);
        t.add_item(&sd, &sr, "plan.pptx", Some(b"slides".to_vec()));
        let team = t.add_team("Project X", &["General"]);
        let ch = t.team(&team).channels[0].0.clone();
        t.add_chat(&team, &ch, &alice, "kickoff", None, None);
        t.add_member(&team, &alice, true);
        t.add_device("ALICE-LAPTOP");
        t.add_application("Payroll");
    }
    let mut cfg = m.config();
    cfg["entra"] = true.into();
    println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
    eprintln!("Graph mock on https://127.0.0.1:{} (Ctrl-C to stop)", m.port);
    loop {
        std::thread::park();
    }
}
