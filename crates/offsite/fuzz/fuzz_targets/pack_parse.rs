//! Pack parsing (`pack::parse`, `footer_index_len`, `remote_path`) on bytes from
//! a hostile Storage Box. Besides raw bytes, the input is also turned into an
//! *authentic* pack whose index plaintext comes from the fuzzer, so the checks
//! after decryption (entry bounds) are exercised too.
#![no_main]

use libfuzzer_sys::fuzz_target;
use offsite::pack;
use offsite_fuzz::keys;

fuzz_target!(|data: &[u8]| {
    let k = keys();
    let _ = pack::footer_index_len(data.get(..8).unwrap_or(data));
    let id = String::from_utf8_lossy(data.get(..data.len().min(40)).unwrap_or_default()).into_owned();
    let _ = pack::remote_path(&id);
    assert!(pack::parse(&k, "00112233445566778899aabbccddeeff", data).is_err());

    // authentic pack: [u16 LE body len][body][index plaintext]
    let Some((l, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let bl = (u16::from_le_bytes(*l) as usize).min(rest.len());
    let (body, plain) = rest.split_at(bl);
    let pid = "0123456789abcdef0123456789abcdef";
    let idx = k.seal(format!("pack:{pid}").as_bytes(), plain);
    let bytes = [
        b"NXP1".as_slice(),
        body,
        &idx,
        &(idx.len() as u32).to_le_bytes(),
        b"NXPI",
    ]
    .concat();
    if let Ok(entries) = pack::parse(&k, pid, &bytes) {
        for e in entries {
            // what verify_sample does with a parsed pack
            let raw = &bytes[e.offset as usize..(e.offset + e.len as u64) as usize];
            let _ = k.open_chunk(&e.id, raw);
        }
    }
});
