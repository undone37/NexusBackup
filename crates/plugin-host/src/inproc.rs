//! In-process peer: a plugin running on a thread of this process, connected through
//! two OS pipes (tests and the SDK's test harness `plugin_sdk::testing`; never used
//! by `nexus-pluginhost`, which always runs plugins in their sandbox).

use crate::sandbox::{reader_thread, Conn, Peer};
use anyhow::Result;
use plugin_proto::Message;
use std::io::{BufWriter, Read, Write};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The plugin's main: runs one operation on (stdin, stdout), e.g. `plugin_sdk::run_with`.
pub type PluginFn = Box<dyn FnOnce(Box<dyn Read + Send>, Box<dyn Write + Send>) + Send>;

/// A [`Peer`] to a plugin on a thread. Dropping it closes the pipes (the thread then
/// ends on EOF); [`Peer::finish`] also joins the thread.
pub struct InProc {
    conn: Option<Conn>,
    thread: Option<JoinHandle<()>>,
}

impl InProc {
    /// Starts `plugin(stdin, stdout)` on a thread.
    pub fn start(plugin: PluginFn, op_timeout: Duration, idle: Option<Duration>) -> Result<InProc> {
        let (host_r, plugin_w) = std::io::pipe()?;
        let (plugin_r, host_w) = std::io::pipe()?;
        let thread = std::thread::spawn(move || plugin(Box::new(plugin_r), Box::new(plugin_w)));
        Ok(InProc {
            conn: Some(Conn {
                inbox: reader_thread(host_r),
                out: Box::new(BufWriter::new(host_w)),
                deadline: Instant::now() + op_timeout,
                idle,
            }),
            thread: Some(thread),
        })
    }

    fn close(&mut self) {
        // dropping both pipe ends lets the plugin thread see EOF / EPIPE and return
        self.conn = None;
    }

    fn conn(&mut self) -> Result<&mut Conn> {
        self.conn
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("plugin connection closed"))
    }
}

impl Peer for InProc {
    fn send(&mut self, m: &Message) -> Result<()> {
        let r = self.conn()?.send(m);
        r.map_err(|e| {
            self.close();
            anyhow::anyhow!("cannot write to the plugin: {e}")
        })
    }
    fn recv(&mut self) -> Result<Message> {
        let r = self.conn()?.recv();
        r.map_err(|e| {
            self.close();
            anyhow::anyhow!("plugin stopped: {e}")
        })
    }
    fn poll(&mut self, wait: Duration) -> Result<Option<Message>> {
        let r = self.conn()?.poll(wait);
        r.map_err(|e| {
            self.close();
            anyhow::anyhow!("plugin stopped: {e}")
        })
    }
    fn set_idle(&mut self, idle: Option<Duration>) {
        if let Some(c) = self.conn.as_mut() {
            c.idle = idle;
        }
    }
    fn violation(&mut self, why: &str) -> anyhow::Error {
        self.close();
        anyhow::anyhow!("plugin stopped: protocol violation: {why}")
    }
    fn finish(&mut self) {
        self.close();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for InProc {
    fn drop(&mut self) {
        self.close();
    }
}
