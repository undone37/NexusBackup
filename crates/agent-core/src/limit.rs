//! Appliance-side limits enforced by the agent (`agent_proto::Limits`): a token
//! bucket on the chunk data sent for `Want` and a lower CPU / I/O priority for the
//! session thread (platform hook `Platform::lower_priority`).

use std::time::{Duration, Instant};

/// Token bucket in bytes: `rate` per second, at most one second of burst. A chunk
/// larger than the bucket is let through once the bucket is full and the debt is
/// paid by the following sends (the average still holds).
pub struct Bucket {
    rate: u64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// `None` for an unlimited rate (0).
    pub fn new(rate: u64, now: Instant) -> Option<Bucket> {
        (rate > 0).then_some(Bucket {
            rate,
            tokens: rate as f64,
            last: now,
        })
    }

    /// Takes `n` bytes; returns how long to wait before sending them.
    pub fn take(&mut self, n: u64, now: Instant) -> Duration {
        let cap = self.rate as f64;
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * cap).min(cap) - n as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / cap)
        }
    }

    /// `take` and sleep.
    pub fn throttle(&mut self, n: u64) {
        let d = self.take(n, Instant::now());
        if !d.is_zero() {
            std::thread::sleep(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_paces_to_the_rate() {
        let t0 = Instant::now();
        assert!(Bucket::new(0, t0).is_none(), "0 = unlimited");
        let mut b = Bucket::new(1000, t0).unwrap();
        // one second of burst is free
        assert_eq!(b.take(1000, t0), Duration::ZERO);
        // the next 500 bytes wait half a second
        assert_eq!(b.take(500, t0), Duration::from_millis(500));
        // after 1.5 s the debt is paid and 1000 bytes are available again... capped at one second of burst
        let t1 = t0 + Duration::from_millis(1500);
        assert_eq!(b.take(1000, t1), Duration::ZERO);
        let t2 = t1 + Duration::from_secs(60);
        assert_eq!(b.take(1000, t2), Duration::ZERO);
        assert_eq!(b.take(1000, t2), Duration::from_secs(1), "burst capped at one second");
        // simulated transfer: 10 kB at 1 kB/s takes ~9 s after the burst (sleeping the returned time)
        let mut b = Bucket::new(1000, t0).unwrap();
        let mut now = t0;
        for _ in 0..10 {
            now += b.take(1000, now);
        }
        assert_eq!(now - t0, Duration::from_secs(9));
        // a chunk larger than the bucket is not starved
        let mut b = Bucket::new(100, t0).unwrap();
        assert_eq!(b.take(1000, t0), Duration::from_secs(9));
    }
}
