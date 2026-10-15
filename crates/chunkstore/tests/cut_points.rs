//! Pins the FastCDC cut points: a fastcdc upgrade that moves them would silently stop
//! deduplicating against every existing backup (new chunk ids for unchanged data).

use chunkstore::store::{CDC_AVG, CDC_MAX, CDC_MIN};

/// 16 MiB of xorshift64 output: deterministic, incompressible, no extra dependency.
fn data() -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    (0..2 << 20)
        .flat_map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()
        })
        .collect()
}

#[test]
fn cut_points_are_stable() {
    let d = data();
    let lens: Vec<usize> = fastcdc::v2020::FastCDC::new(&d, CDC_MIN as _, CDC_AVG as _, CDC_MAX as _)
        .map(|c| c.length)
        .collect();
    assert_eq!(lens.iter().sum::<usize>(), d.len());
    assert_eq!(
        lens, EXPECTED,
        "FastCDC cut points changed: existing backups would no longer deduplicate"
    );
}

/// Recorded with fastcdc 3.2.1 and 5.0.0 (identical).
const EXPECTED: &[usize] = &[
    532150, 618582, 592791, 671048, 540917, 1027048, 604807, 824540, 621740, 958782, 786717, 313935, 874566, 784458,
    750720, 880996, 661135, 586331, 790819, 215202, 142944, 863546, 664561, 718018, 698848, 52015,
];
