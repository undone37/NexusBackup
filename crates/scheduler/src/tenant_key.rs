//! Tenant recovery key (Phase 17e, docs/control-plane.md): before each
//! offsite run the tenant's public key from the catalog goes to keyd, which
//! seals every DEK version to it; the sealed files then travel with the
//! normal escrow. A replaced or removed key's files leave the escrow dir (and
//! `nexus-offsite upload` prunes them on the box).

use catalog::Catalog;
use std::fs;
use std::path::Path;

/// Hands the catalog's tenant recovery public key (or its absence) to keyd.
pub(crate) fn sync(db: &Catalog, socket: &Path, tenant: &str) {
    // Phase 30: X25519 + ML-KEM-768 when the key has its post-quantum half
    let public = match catalog::tenant_key::get(&db.conn(), tenant) {
        Ok(s) => s.and_then(|s| catalog::tenant_key::sealing_key(&s)),
        Err(e) => {
            eprintln!("<4>scheduler: tenant recovery key of {tenant}: {e}");
            return;
        }
    };
    match keyd::request_tenant_recovery(socket, tenant, public.as_deref()) {
        Ok(true) => eprintln!(
            "scheduler: tenant {tenant}: recovery key {} in keyd",
            public.map_or("removed".to_owned(), |p| format!(
                "set (id {}{})",
                keyd::tenant_key::key_id(&p),
                if p.len() > 32 { ", X25519 + ML-KEM-768" } else { "" }
            ))
        ),
        Ok(false) => {}
        // tests / keyd down: the escrow refresh that follows fails the same way
        Err(_) => {}
    }
}

/// Removes tenant escrow files keyd no longer lists (replaced or removed key).
pub(crate) fn prune_escrow_dir(dir: &Path, tenant: &str, files: &[(String, Vec<u8>)]) {
    let td = dir.join("tenants").join(tenant);
    let Ok(rd) = fs::read_dir(&td) else { return };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if keyd::tenant_key::is_escrow_file(&n) && !files.iter().any(|(f, _)| f == &format!("tenants/{tenant}/{n}")) {
            let _ = fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn sync_and_prune() {
        let d = tempfile::tempdir().unwrap();
        let kd = d.path().join("keyd");
        keyd::init(&kd).unwrap();
        keyd::create_tenant(&kd, "acme").unwrap();
        let sock = d.path().join("k.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let dir = kd.clone();
        // keyd's answers without the peer check
        let srv = std::thread::spawn(move || {
            for c in l.incoming().take(3) {
                let mut c = c.unwrap();
                let mut line = String::new();
                let mut r = std::io::BufReader::new(&c);
                std::io::BufRead::read_line(&mut r, &mut line).unwrap();
                // `tenant-recovery-pq <t> <len>` carries the hybrid key as its body
                let mut body = vec![0u8; 0];
                if line.starts_with("tenant-recovery-pq ") {
                    body.resize(line.trim_end().rsplit(' ').next().unwrap().parse().unwrap(), 0);
                    std::io::Read::read_exact(&mut r, &mut body).unwrap();
                }
                if let Ok(a) = keyd::answer_with_body(&dir, &line, &body) {
                    std::io::Write::write_all(&mut c, &a).unwrap();
                }
            }
        });
        let db = Catalog::open_memory().unwrap();
        let (key, public, pq) = catalog::tenant_key::generate();
        // the catalog derives the ML-KEM half exactly like keyd
        let want: String = keyd::tenant_key::hybrid_public_of(&key).unwrap()[32..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(pq, want);
        let st = catalog::tenant_key::Status {
            kid: public[..16].to_owned(),
            public,
            public_pq: Some(pq),
            set_at: 1,
            requested_by: "a".into(),
            approved_by: "b".into(),
            quorum: 1,
        };
        catalog::tenant_key::put(&db.conn(), "acme", &st).unwrap();
        sync(&db, &sock, "acme");
        let files = keyd::fetch_escrow(&sock, "acme").unwrap();
        assert!(files.iter().any(
            |(n, b)| keyd::tenant_key::is_escrow_file(n.rsplit('/').next().unwrap()) && keyd::hybrid::is_hybrid(b)
        ));
        let tenant_files: Vec<_> = files
            .iter()
            .filter_map(|(n, b)| Some((n.strip_prefix("tenants/acme/")?.to_owned(), b.clone())))
            .collect();
        assert_eq!(keyd::tenant_key::open("acme", &key, &tenant_files).unwrap().len(), 1);
        // a stale file of an old key goes, the current ones stay
        let esc = d.path().join("escrow");
        fs::create_dir_all(esc.join("tenants/acme")).unwrap();
        fs::write(esc.join("tenants/acme/tenant-escrow.0000000000000000.1"), b"old").unwrap();
        fs::write(esc.join("tenants/acme/dek.1"), b"x").unwrap();
        prune_escrow_dir(&esc, "acme", &files);
        assert!(!esc.join("tenants/acme/tenant-escrow.0000000000000000.1").exists());
        assert!(esc.join("tenants/acme/dek.1").exists());
        // removed in the catalog: keyd drops it too
        catalog::tenant_key::remove(&db.conn(), "acme").unwrap();
        sync(&db, &sock, "acme");
        srv.join().unwrap();
        assert!(keyd::tenant_key::current(&kd, "acme").unwrap().is_none());
    }
}
