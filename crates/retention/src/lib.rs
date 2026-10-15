//! GFS retention (plan §10), period-based like PBS / `borg prune`: "14 daily"
//! keeps the last snapshot of each of the last 14 days *that have a snapshot*.
//! A snapshot may be daily, weekly, monthly and yearly at once; the union is kept.
//! `recent` (hours) keeps *every* snapshot of the last N hours before the newest
//! one (frequent WAL-only database runs), on top of the period classes.

#![warn(missing_docs)]

// ponytail: periods are computed in UTC; a per-appliance time zone when customers notice.

use std::collections::BTreeMap;

/// GFS retention policy: how many periods of each class to keep. 0 disables a class.
#[derive(Clone, Copy, Debug)]
pub struct Gfs {
    /// keep all snapshots of the last N hours (counted back from the newest snapshot)
    pub recent: u32,
    /// keep the last snapshot of each of the last N days that have a snapshot (UTC days)
    pub daily: u32,
    /// keep the last snapshot of each of the last N weeks that have one (weeks start Monday, UTC)
    pub weekly: u32,
    /// keep the last snapshot of each of the last N calendar months that have one (UTC)
    pub monthly: u32,
    /// keep the last snapshot of each of the last N calendar years that have one (UTC)
    pub yearly: u32,
}

impl Default for Gfs {
    fn default() -> Self {
        Gfs {
            recent: 0,
            daily: 14,
            weekly: 4,
            monthly: 6,
            yearly: 2,
        }
    }
}

/// Retention class a kept snapshot holds; one snapshot can hold several. Ordered from shortest to longest lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// within the last `recent` hours before the newest snapshot
    Recent,
    /// last snapshot of its UTC day
    Daily,
    /// last snapshot of its week (Monday to Sunday, UTC)
    Weekly,
    /// last snapshot of its calendar month
    Monthly,
    /// last snapshot of its calendar year
    Yearly,
}

impl Class {
    /// Lock duration a snapshot gets when classified (plan §5.5 / §10). `Recent`
    /// adds nothing: such a snapshot keeps its commit lock (the store's minimum).
    pub fn lock_secs(self) -> u64 {
        const DAY: u64 = 86400;
        match self {
            Class::Recent => 0,
            Class::Daily => 14 * DAY,
            Class::Weekly => 28 * DAY,
            Class::Monthly => 183 * DAY,
            Class::Yearly => 730 * DAY,
        }
    }
}

/// Unix days -> (year, month) in the proleptic Gregorian calendar (H. Hinnant).
pub fn civil(days: i64) -> (i64, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m)
}

fn period(class: Class, t: u64) -> i64 {
    let days = (t / 86400) as i64;
    match class {
        Class::Daily => days,
        Class::Weekly => (days + 3).div_euclid(7), // weeks start Monday (1970-01-01 was a Thursday)
        Class::Monthly => {
            let (y, m) = civil(days);
            y * 12 + m as i64
        }
        Class::Yearly => civil(days).0,
        Class::Recent => t as i64, // unused: every snapshot is its own period
    }
}

/// Snapshot times to keep, each with the classes it holds. Everything not in
/// the result may be pruned (subject to its retention lock).
pub fn keep(times: &[u64], p: &Gfs) -> BTreeMap<u64, Vec<Class>> {
    let mut sorted = times.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a)); // newest first
    sorted.dedup();
    let mut out: BTreeMap<u64, Vec<Class>> = BTreeMap::new();
    if let (Some(&newest), true) = (sorted.first(), p.recent > 0) {
        let from = newest.saturating_sub(u64::from(p.recent) * 3600);
        for &t in sorted.iter().take_while(|t| **t > from) {
            out.entry(t).or_default().push(Class::Recent);
        }
    }
    for (class, n) in [
        (Class::Daily, p.daily),
        (Class::Weekly, p.weekly),
        (Class::Monthly, p.monthly),
        (Class::Yearly, p.yearly),
    ] {
        let mut last = None;
        let mut left = n;
        for &t in &sorted {
            if left == 0 {
                break;
            }
            let per = period(class, t);
            if last != Some(per) {
                last = Some(per);
                left -= 1;
                out.entry(t).or_default().push(class);
            }
        }
    }
    out
}

/// Lock a kept snapshot needs: the longest of its classes, from snapshot time.
pub fn lock_until(time: u64, classes: &[Class]) -> u64 {
    time + classes.iter().map(|c| c.lock_secs()).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    const DAY: u64 = 86400;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1));
        assert_eq!(civil(20_371), (2025, 10)); // 2025-10-09
        assert_eq!(civil(11_016), (2000, 2)); // 2000-02-29
        assert_eq!(civil(-1), (1969, 12));
    }

    #[test]
    fn daily_for_two_years_gives_14_4_6_2() {
        // one snapshot per day at 22:00 for 800 days, ending 2026-10-08
        let end = 20_734 * DAY + 22 * 3600;
        let times: Vec<u64> = (0..800).map(|i| end - i * DAY).collect();
        let k = keep(&times, &Gfs::default());
        let count = |c| k.values().filter(|v| v.contains(&c)).count();
        assert_eq!(
            (
                count(Class::Daily),
                count(Class::Weekly),
                count(Class::Monthly),
                count(Class::Yearly)
            ),
            (14, 4, 6, 2)
        );
        assert!(k[&end].len() == 4, "newest is daily+weekly+monthly+yearly");
        assert!(k.len() < 14 + 4 + 6 + 2, "overlaps are shared");
    }

    #[test]
    fn gaps_do_not_prune_old_restore_points() {
        // backups stopped 60 days ago: still 14 dailies (the last 14 days *with* backups)
        let end = 20_000 * DAY;
        let times: Vec<u64> = (0..30).map(|i| end - i * DAY).collect();
        let k = keep(
            &times,
            &Gfs {
                recent: 0,
                daily: 14,
                weekly: 0,
                monthly: 0,
                yearly: 0,
            },
        );
        assert_eq!(k.len(), 14);
        assert_eq!(*k.keys().next().unwrap(), end - 13 * DAY);
    }

    #[test]
    fn last_snapshot_of_a_day_wins() {
        let d = 20_000 * DAY;
        let k = keep(
            &[d + 100, d + 5000, d + 3000, d - 10],
            &Gfs {
                recent: 0,
                daily: 2,
                weekly: 0,
                monthly: 0,
                yearly: 0,
            },
        );
        assert_eq!(k.keys().copied().collect::<Vec<_>>(), vec![d - 10, d + 5000]);
        assert_eq!(lock_until(d, &[Class::Daily, Class::Monthly]), d + 183 * DAY);
    }

    #[test]
    fn recent_keeps_every_snapshot_of_the_last_hours() {
        // every 15 minutes for 3 days
        let end = 20_000 * DAY + 12 * 3600;
        let times: Vec<u64> = (0..3 * 96).map(|i| end - i * 900).collect();
        let g = Gfs {
            recent: 24,
            daily: 7,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        };
        let k = keep(&times, &g);
        let recent: Vec<u64> = k
            .iter()
            .filter(|(_, c)| c.contains(&Class::Recent))
            .map(|(t, _)| *t)
            .collect();
        assert_eq!(recent.len(), 96, "24 h of 15-minute snapshots");
        assert!(recent.iter().all(|t| *t > end - 24 * 3600));
        // older ones: one per day (the last of each day); 72 h from noon span 4 days, the
        // last snapshots of the newest two are recent anyway
        assert_eq!(k.len(), 96 + 2, "2 older days add their last snapshot");
        assert!(k[&end].contains(&Class::Daily) && k[&end].contains(&Class::Recent));
        // the recent class adds no lock beyond the snapshot time (the commit lock stays)
        assert_eq!(lock_until(end - 900, &[Class::Recent]), end - 900);
        assert_eq!(lock_until(end, &[Class::Recent, Class::Daily]), end + 14 * DAY);
        let k0 = keep(&times, &Gfs { recent: 0, ..g });
        assert_eq!(k0.len(), 4, "without recent: one per day");
    }
}
