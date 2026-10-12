use super::*;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

/// 2026-06-01, inside the default validity below
const NOW: i64 = 1_780_272_000;

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d
}

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca(cn: &str, parent: Option<&Ca>) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2035, 1, 1);
    let cert = match parent {
        Some(i) => p.signed_by(&key, &i.cert, &i.key).unwrap(),
        None => p.self_signed(&key).unwrap(),
    };
    Ca { cert, key }
}

struct Leaf<'a> {
    sans: &'a [&'a str],
    from: i32,
    to: i32,
    eku: Vec<ExtendedKeyUsagePurpose>,
}

impl Default for Leaf<'_> {
    fn default() -> Self {
        Leaf {
            sans: &["backup.example.com", "198.51.100.5"],
            from: 2025,
            to: 2027,
            eku: vec![ExtendedKeyUsagePurpose::ServerAuth],
        }
    }
}

fn leaf(key: &KeyPair, issuer: &Ca, l: Leaf) -> Certificate {
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(l.sans[0]);
    for s in l.sans {
        p.subject_alt_names.push(match s.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName((*s).try_into().unwrap()),
        });
    }
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = l.eku;
    p.not_before = rcgen::date_time_ymd(l.from, 1, 1);
    p.not_after = rcgen::date_time_ymd(l.to, 1, 1);
    p.signed_by(key, &issuer.cert, &issuer.key).unwrap()
}

fn names() -> Vec<String> {
    vec!["backup.example.com".into(), "198.51.100.5".into()]
}

fn pems(cs: &[&Certificate]) -> String {
    cs.iter().map(|c| c.pem()).collect()
}

fn err(r: Result<Valid>) -> String {
    format!("{:#}", r.unwrap_err())
}

#[test]
fn complete_chain_with_and_without_root() {
    let (root, key) = (ca("Root", None), KeyPair::generate().unwrap());
    let int = ca("Intermediate", Some(&root));
    let l = leaf(&key, &int, Leaf::default());
    let v = validate(&pems(&[&l, &int.cert, &root.cert]), &key.serialize_pem(), &names(), NOW).unwrap();
    assert_eq!(v.chain.len(), 3);
    assert!(v.warnings.is_empty(), "{:?}", v.warnings);
    assert_eq!(v.chain[0].sans, names());
    assert!(v.chain[2].self_signed && !v.chain[0].ca);
    assert_eq!(v.chain[0].sha256, fingerprint(l.der()));
    // the re-encoded PEM parses to the same certificates
    assert_eq!(chain_info(v.pem.as_bytes()).unwrap(), v.chain);

    let v = validate(&pems(&[&l, &int.cert]), &key.serialize_pem(), &names(), NOW).unwrap();
    assert_eq!(v.warnings.len(), 1, "root left out: warned, accepted");
}

#[test]
fn wrong_order_and_missing_intermediate() {
    let (root, key) = (ca("Root", None), KeyPair::generate().unwrap());
    let int = ca("Intermediate", Some(&root));
    let l = leaf(&key, &int, Leaf::default());
    let k = key.serialize_pem();
    assert!(err(validate(&pems(&[&int.cert, &l]), &k, &names(), NOW)).contains("wrong order"));
    assert!(err(validate(&pems(&[&l, &root.cert, &int.cert]), &k, &names(), NOW)).contains("wrong order"));
    assert!(err(validate(&pems(&[&l, &root.cert]), &k, &names(), NOW)).contains("not a chain"));
}

#[test]
fn key_must_match() {
    let (root, key, other) = (ca("Root", None), KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let l = leaf(&other, &root, Leaf::default());
    let e = err(validate(&pems(&[&l, &root.cert]), &key.serialize_pem(), &names(), NOW));
    assert!(e.contains("does not belong to the pending key"), "{e}");
}

#[test]
fn names_must_be_covered() {
    let (root, key) = (ca("Root", None), KeyPair::generate().unwrap());
    let k = key.serialize_pem();
    let l = leaf(
        &key,
        &root,
        Leaf {
            sans: &["backup.example.com"],
            ..Default::default()
        },
    );
    let e = err(validate(&pems(&[&l, &root.cert]), &k, &names(), NOW));
    assert!(e.contains("does not cover 198.51.100.5"), "{e}");
    // a wildcard covers one label
    let l = leaf(
        &key,
        &root,
        Leaf {
            sans: &["*.example.com", "198.51.100.5"],
            ..Default::default()
        },
    );
    validate(&pems(&[&l, &root.cert]), &k, &names(), NOW).unwrap();
    assert!(!covers("*.example.com", "a.b.example.com"));
    assert!(!covers("*.example.com", "example.com"));
    assert!(covers("2001:db8::1", "2001:0db8:0:0::1"));
}

#[test]
fn validity_and_usage() {
    let (root, key) = (ca("Root", None), KeyPair::generate().unwrap());
    let k = key.serialize_pem();
    let expired = leaf(
        &key,
        &root,
        Leaf {
            from: 2021,
            to: 2022,
            ..Default::default()
        },
    );
    assert!(err(validate(&pems(&[&expired, &root.cert]), &k, &names(), NOW)).contains("has expired"));
    let future = leaf(
        &key,
        &root,
        Leaf {
            from: 2027,
            to: 2028,
            ..Default::default()
        },
    );
    assert!(err(validate(&pems(&[&future, &root.cert]), &k, &names(), NOW)).contains("not valid yet"));
    let client = leaf(
        &key,
        &root,
        Leaf {
            eku: vec![ExtendedKeyUsagePurpose::ClientAuth],
            ..Default::default()
        },
    );
    assert!(err(validate(&pems(&[&client, &root.cert]), &k, &names(), NOW)).contains("serverAuth"));
    assert!(err(validate("garbage", &k, &names(), NOW)).contains("no certificate"));
}

#[test]
fn csr_install_revert() {
    let d = tempfile::tempdir().unwrap();
    let p = Paths {
        tls: d.path().join("tls"),
        req: d.path().join("req"),
    };
    fs::create_dir_all(&p.tls).unwrap();
    fs::create_dir_all(&p.req).unwrap();
    let root = ca("Root", None);
    let self_signed = ca("backup.example.com", None);
    fs::write(p.identity(), self_signed.cert.pem()).unwrap();
    assert_eq!(status(&p).unwrap()["active"], "self_signed");
    assert!(revert(&p).is_err(), "nothing to revert");

    // the web-api's request file, answered by process()
    let req = json!({"id": "01", "op": "csr", "cn": "backup.example.com", "sans": ["198.51.100.5", "BACKUP.example.com"]});
    fs::write(p.request(), req.to_string()).unwrap();
    assert!(process(&p).unwrap());
    assert!(!p.request().exists());
    let r: Value = serde_json::from_slice(&fs::read(p.result()).unwrap()).unwrap();
    assert_eq!((r["id"].as_str(), r["ok"].as_bool()), (Some("01"), Some(true)), "{r}");
    assert_eq!(r["pending"]["sans"], json!(["backup.example.com", "198.51.100.5"]));
    let csr_pem = r["csr_pem"].as_str().unwrap();
    assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
    assert_eq!(status(&p).unwrap()["pending"]["csr_pem"], csr_pem);

    // the CA signs the CSR's key (here: the pending key itself)
    let key = KeyPair::from_pem(&fs::read_to_string(p.pending().join("key.pem")).unwrap()).unwrap();
    let mut l = leaf(&key, &root, Leaf::default());
    // a failed install keeps the pending key
    let bad = install(&p, &pems(&[&leaf(&key, &root, Leaf { sans: &["x.example.com"], ..Default::default() })]), NOW);
    assert!(bad.is_err() && p.pending().join("key.pem").exists());
    install(&p, &pems(&[&l, &root.cert]), NOW).unwrap();
    assert!(!p.pending().exists() && !p.csr().exists());
    let s = status(&p).unwrap();
    assert_eq!(s["active"], "imported");
    assert_eq!(s["chain"][0]["sha256"], fingerprint(l.der()));
    assert_eq!(s["identity"]["sha256"], fingerprint(self_signed.cert.der()));
    let web = fs::read_to_string(p.web()).unwrap();
    assert!(web.contains("BEGIN CERTIFICATE") && web.contains("PRIVATE KEY"));

    // second import: the first becomes the previous one
    csr(&p, "backup.example.com", &["198.51.100.5".into()]).unwrap();
    let key2 = KeyPair::from_pem(&fs::read_to_string(p.pending().join("key.pem")).unwrap()).unwrap();
    let l2 = leaf(&key2, &root, Leaf::default());
    install(&p, &pems(&[&l2]), NOW).unwrap();
    let first = |p: &Paths| status(p).unwrap()["chain"][0]["sha256"].as_str().unwrap().to_owned();
    assert_eq!(first(&p), fingerprint(l2.der()));
    assert_eq!(revert(&p).unwrap()["active"], "imported");
    assert_eq!(first(&p), fingerprint(l.der()));
    assert_eq!(revert(&p).unwrap()["active"], "imported");
    assert_eq!(first(&p), fingerprint(l2.der()), "revert toggles");

    // without a previous one, revert goes back to self-signed (and can be undone)
    fs::remove_file(p.prev()).unwrap();
    assert_eq!(revert(&p).unwrap()["active"], "self_signed");
    assert_eq!(first(&p), fingerprint(self_signed.cert.der()));
    assert_eq!(revert(&p).unwrap()["active"], "imported");
    l = l2;
    assert_eq!(first(&p), fingerprint(l.der()));

    // errors are answered, not fatal
    fs::write(p.request(), json!({"id": "02", "op": "install", "chain_pem": "x"}).to_string()).unwrap();
    assert!(process(&p).unwrap());
    let r: Value = serde_json::from_slice(&fs::read(p.result()).unwrap()).unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["error"].as_str().unwrap().contains("no pending key"));
    assert!(!process(&p).unwrap(), "no request");
}

#[test]
fn names_checked() {
    assert_eq!(check_name("Backup.Example.com.").unwrap(), "backup.example.com");
    assert_eq!(check_name("*.example.com").unwrap(), "*.example.com");
    assert!(check_name("a b").is_err() && check_name("-x.com").is_err() && check_name("").is_err());
    assert!(make_csr("ok.example.com", &["bad name".into()]).is_err());
}
