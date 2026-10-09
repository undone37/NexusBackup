//! VSS writer reporting (pure, tested on Linux): writer state names, which writers are
//! application writers the UI must highlight, and the `Prepared.hook_log` summary.

use agent_proto::VssWriter;

/// `VSS_WRITER_STATE` → stable text.
pub fn state_name(s: i32) -> &'static str {
    match s {
        1 => "stable",
        2 => "waiting_for_freeze",
        3 => "waiting_for_thaw",
        4 => "waiting_for_post_snapshot",
        5 => "waiting_for_backup_complete",
        6 => "failed_at_identify",
        7 => "failed_at_prepare_backup",
        8 => "failed_at_prepare_snapshot",
        9 => "failed_at_freeze",
        10 => "failed_at_thaw",
        11 => "failed_at_post_snapshot",
        12 => "failed_at_backup_complete",
        13 => "failed_at_pre_restore",
        14 => "failed_at_post_restore",
        15 => "failed_at_backup_shutdown",
        _ => "unknown",
    }
}

pub fn is_failed_state(s: i32) -> bool {
    (6..=15).contains(&s)
}

/// Well-known writer class ids (lower case, braces) of application writers whose data
/// is only application-consistent if the writer took part.
const APPLICATION_WRITERS: [(&str, &str); 3] = [
    ("{a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}", "SqlServerWriter"),
    ("{76fe1ac4-15f7-4bcd-987e-8e1acb462fb7}", "Microsoft Exchange Writer"),
    ("{b2014c9e-8711-4c5c-a5a9-3cf384484757}", "NTDS"),
];

/// SQL Server, Exchange (incl. the replica writer), Active Directory: by class id,
/// or by name.
pub fn is_application_writer(class_id: &str, name: &str) -> bool {
    let id = class_id.to_ascii_lowercase();
    APPLICATION_WRITERS
        .iter()
        .any(|(i, n)| *i == id || n.eq_ignore_ascii_case(name))
        || name.starts_with("SqlServerWriter")
        || name.starts_with("Microsoft Exchange")
}

/// Parse `vss_exclude_writers` (comma separated class ids) into normalised ids.
pub fn parse_exclusions(s: &str) -> Result<Vec<String>, String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|x| {
            let id = x.trim_matches(['{', '}']).to_ascii_lowercase();
            let ok = id.len() == 36
                && id.char_indices().all(|(i, c)| {
                    if [8, 13, 18, 23].contains(&i) {
                        c == '-'
                    } else {
                        c.is_ascii_hexdigit()
                    }
                });
            ok.then(|| format!("{{{id}}}"))
                .ok_or_else(|| format!("vss_exclude_writers: {x:?} is not a writer class id"))
        })
        .collect()
}

/// Human-readable writer report for `Prepared.hook_log`, worst first.
pub fn summary(writers: &[VssWriter]) -> String {
    let mut w: Vec<&VssWriter> = writers.iter().collect();
    w.sort_by_key(|x| (x.participated && x.failure.is_empty(), !x.application, x.name.clone()));
    let ok = writers
        .iter()
        .filter(|x| x.participated && x.failure.is_empty())
        .count();
    let mut s = format!("VSS writers: {ok} of {} participated\n", writers.len());
    for x in w {
        let status = if !x.participated {
            "EXCLUDED"
        } else if !x.failure.is_empty() {
            "FAILED"
        } else {
            "ok"
        };
        s.push_str(&format!(
            "  [{status}] {}{} {} ({}){}{}\n",
            x.name,
            if x.instance.is_empty() {
                String::new()
            } else {
                format!(" / {}", x.instance)
            },
            x.class_id,
            x.state,
            if x.failure.is_empty() {
                String::new()
            } else {
                format!(" error {}", x.failure)
            },
            if x.application && (status != "ok") {
                " — application data is only crash-consistent"
            } else {
                ""
            }
        ));
    }
    s
}

/// `consistent` for `Prepared`: false if an application writer failed.
pub fn all_application_writers_ok(writers: &[VssWriter]) -> bool {
    writers
        .iter()
        .filter(|w| w.application && w.participated)
        .all(|w| w.failure.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(name: &str, id: &str, participated: bool, failure: &str) -> VssWriter {
        VssWriter {
            name: name.into(),
            class_id: id.into(),
            instance: String::new(),
            participated,
            state: if failure.is_empty() {
                "stable"
            } else {
                "failed_at_freeze"
            }
            .into(),
            failure: failure.into(),
            application: is_application_writer(id, name),
        }
    }

    #[test]
    fn states_and_application_writers() {
        assert_eq!(state_name(1), "stable");
        assert_eq!(state_name(9), "failed_at_freeze");
        assert_eq!(state_name(99), "unknown");
        assert!(is_failed_state(8) && !is_failed_state(5));
        assert!(is_application_writer("{A65FAA63-5EA8-4EBC-9DBD-A0C4DB26912A}", "x"));
        assert!(is_application_writer("{00000000-0000-0000-0000-000000000000}", "NTDS"));
        assert!(is_application_writer("", "Microsoft Exchange Writer"));
        assert!(!is_application_writer(
            "{e8132975-6f93-4464-a53e-1050253ae220}",
            "System Writer"
        ));
    }

    #[test]
    fn exclusions() {
        assert_eq!(
            parse_exclusions(" {A65FAA63-5EA8-4EBC-9DBD-A0C4DB26912A}, e8132975-6f93-4464-a53e-1050253ae220 ").unwrap(),
            vec![
                "{a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}".to_string(),
                "{e8132975-6f93-4464-a53e-1050253ae220}".to_string()
            ]
        );
        assert_eq!(parse_exclusions("").unwrap(), Vec::<String>::new());
        assert!(parse_exclusions("SqlServerWriter").is_err());
        assert!(parse_exclusions("{a65faa63-5ea8-4ebc-9dbd-a0c4db26912}").is_err());
    }

    #[test]
    fn summary_and_consistency() {
        let ws = vec![
            w("System Writer", "{e8132975-6f93-4464-a53e-1050253ae220}", true, ""),
            w(
                "SqlServerWriter",
                "{a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}",
                true,
                "0x800423f4 VSS_E_WRITERERROR_RETRYABLE",
            ),
            w("NTDS", "{b2014c9e-8711-4c5c-a5a9-3cf384484757}", false, ""),
        ];
        let s = summary(&ws);
        assert!(s.starts_with("VSS writers: 1 of 3 participated\n"), "{s}");
        let lines: Vec<&str> = s.lines().collect();
        assert!(
            lines[1].contains("[EXCLUDED] NTDS") || lines[1].contains("[FAILED] SqlServerWriter"),
            "{s}"
        );
        assert!(s.contains("[FAILED] SqlServerWriter"));
        assert!(s.contains("crash-consistent"));
        assert!(s.contains("[ok] System Writer"));
        assert!(!all_application_writers_ok(&ws));
        assert!(all_application_writers_ok(&ws[..1]));
        assert!(
            all_application_writers_ok(&[ws[0].clone(), ws[2].clone()]),
            "excluded on purpose is not a failure"
        );
    }
}
