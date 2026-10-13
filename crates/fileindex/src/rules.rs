//! Per-source include/exclude rules for the search index (Cohesity syntax,
//! docs/file-index-v2-plan.md "31b: per-group index scope"): `/` separators on
//! Windows too, `/C/…` one drive, `/…` every drive, `*` (and `?`) inside one
//! component, the most specific (longest) matching rule wins, an exclude wins
//! a tie. Matching ignores case. The defaults apply to VM, container and
//! agent sources; NAS shares and plugins have none (their top directories
//! are not a system's).

use index_proto::{source_kind, SourceRules, DEFAULT_EXCLUDES};

struct Rule {
    comps: Vec<String>,
    include: bool,
}

pub struct Rules {
    enabled: bool,
    rules: Vec<Rule>,
}

fn comps(p: &str) -> Vec<String> {
    p.split('/')
        .filter(|c| !c.is_empty())
        .map(|c| c.to_lowercase())
        .collect()
}

/// `*` any run, `?` one character, within one component (lowercase input).
fn glob(p: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut i, mut j) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while j < s.len() {
        if i < p.len() && (p[i] == '?' || p[i] == s[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            back = Some((i + 1, j));
            i += 1;
        } else if let Some((bi, bj)) = back {
            back = Some((bi, bj + 1));
            i = bi;
            j = bj + 1;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == '*')
}

impl Rules {
    pub fn new(source: &str, r: &SourceRules) -> Rules {
        let mut rules = Vec::new();
        if r.defaults && matches!(source_kind(source), "vm" | "ct" | "host") {
            rules.extend(DEFAULT_EXCLUDES.iter().map(|p| Rule {
                comps: comps(p),
                include: false,
            }));
        }
        rules.extend(r.exclude.iter().map(|p| Rule {
            comps: comps(p),
            include: false,
        }));
        rules.extend(r.include.iter().map(|p| Rule {
            comps: comps(p),
            include: true,
        }));
        Rules {
            enabled: r.enabled,
            rules,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a guest path (`/etc/x`, `C:/Users/x`, `Data/x`, `vol3/x`) is indexed.
    pub fn allows(&self, guest: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if self.rules.is_empty() {
            return true;
        }
        let all = comps(guest);
        // a drive (`C:`, a volume label, vol<N>): also matched without it
        let drive = !guest.starts_with('/') && !all.is_empty();
        // the drive-specific form keeps the drive as a component, so a
        // `/C/…` rule is longer (more specific) than the same `/…` rule
        let mut forms: Vec<Vec<String>> = Vec::new();
        if drive {
            let mut with = all.clone();
            with[0] = with[0].trim_end_matches(':').to_owned();
            forms.push(with);
            forms.push(all[1..].to_vec());
        } else {
            forms.push(all);
        }
        let mut best: Option<(usize, bool)> = None;
        for r in &self.rules {
            for p in &forms {
                if r.comps.len() <= p.len() && r.comps.iter().zip(p).all(|(a, b)| glob(a, b)) {
                    let spec = r.comps.len();
                    let better = match best {
                        None => true,
                        Some((s, inc)) => spec > s || (spec == s && inc && !r.include),
                    };
                    if better {
                        best = Some((spec, r.include));
                    }
                }
            }
        }
        best.is_none_or(|(_, inc)| inc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(src: &str, inc: &[&str], exc: &[&str]) -> Rules {
        Rules::new(
            src,
            &SourceRules {
                include: inc.iter().map(|s| s.to_string()).collect(),
                exclude: exc.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
        )
    }

    #[test]
    fn defaults_keep_var_and_hide_system_trees() {
        let r = rules("vm-100", &[], &[]);
        assert!(r.allows("/var/lib/mysql/ibdata1"));
        assert!(r.allows("/var/www/index.html"));
        assert!(!r.allows("/var/cache/apt/x"));
        assert!(!r.allows("/usr/bin/ls"));
        assert!(!r.allows("/proc"));
        assert!(r.allows("/home/ann/report.docx"));
        assert!(!r.allows("C:/Windows/System32/x.dll"));
        assert!(!r.allows("C:/Users/ann/AppData/Local/x"));
        assert!(r.allows("C:/Users/ann/Documents/x.docx"));
        assert!(!r.allows("Data/$Recycle.Bin/S-1-5/x"), "all drives");
        assert!(!r.allows("C:/program files/x"), "case-insensitive");
        // shares and plugins: no defaults
        assert!(rules("share-4", &[], &[]).allows("/tmp/x"));
    }

    #[test]
    fn most_specific_wins() {
        let r = rules(
            "vm-1",
            &["/var/cache/important", "/C/Windows/Temp"],
            &["/srv/*/logs", "/D/Data"],
        );
        assert!(r.allows("/var/cache/important/a"));
        assert!(!r.allows("/var/cache/other"));
        assert!(!r.allows("/srv/web/logs/a.log") && r.allows("/srv/web/htdocs/a"));
        assert!(r.allows("C:/Windows/Temp/x") && !r.allows("C:/Windows/x"));
        assert!(!r.allows("D:/Data/x") && r.allows("E:/Data/x"), "drive-specific");
        let off = Rules::new(
            "vm-1",
            &SourceRules {
                enabled: false,
                ..Default::default()
            },
        );
        assert!(!off.allows("/home/x"));
        let none = Rules::new(
            "vm-1",
            &SourceRules {
                defaults: false,
                ..Default::default()
            },
        );
        assert!(none.allows("/usr/bin/ls"));
        assert!(glob("ab*c?", "abxxcd") && !glob("a*b", "ac"));
    }
}
