//! Agent certificate renewal (Phase 15f, docs/agent-protocol.md "Certificate
//! renewal"): every agent session reports the presented certificate
//! (`agent-cert {json}` from nexus-agentctl), which keeps `agents.cert_issued` /
//! `cert_expires` current; an `agent_renew` job is queued when less than 30 days
//! or 10 % of the lifetime are left (or by "Renew certificate now"). The job's
//! `renew-issued` line makes the new fingerprint a second pin before the agent
//! swaps; `renewed` (or the next session presenting it) makes it the only one.

use super::*;
use crate::expiry::DAY;

/// Renew when less than 30 days or less than a tenth of the lifetime are left.
pub fn renewal_due(issued: Option<i64>, expires: i64, now: i64) -> bool {
    let left = expires - now;
    left < 30 * DAY || issued.is_some_and(|i| expires > i && left < (expires - i) / 10)
}

/// A failed automatic renewal is retried after this long.
const RETRY_SECS: i64 = DAY;

fn fingerprint(v: &Value) -> Option<&str> {
    v["cert_sha256"]
        .as_str()
        .filter(|f| f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Scheduler {
    /// Queues `agent_renew` for enrolled agents whose certificate is due, unless a
    /// renewal / enrollment of that agent is pending or failed within a day.
    pub(crate) fn queue_agent_renewals(&self, now: i64) -> Result<()> {
        let due: Vec<(String, String)> = {
            let c = self.db.conn();
            let mut q = c.prepare(
                "SELECT id, tenant, cert_issued, cert_expires FROM agents \
                 WHERE cert_sha256 IS NOT NULL AND cert_expires IS NOT NULL",
            )?;
            let rows = q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?;
            rows.filter_map(|r| r.ok())
                .filter(|(_, _, issued, expires)| renewal_due(*issued, *expires, now))
                .map(|(id, tenant, _, _)| (id, tenant))
                .collect()
        };
        for (id, tenant) in due {
            let busy: bool = self.db.conn().query_row(
                "SELECT EXISTS (SELECT 1 FROM jobs WHERE kind IN ('agent_renew','agent_enroll') \
                 AND json_extract(params,'$.agent_id') = ?1 \
                 AND (state IN ('queued','running') OR (state = 'failed' AND finished > ?2)))",
                params![id, now - RETRY_SECS],
                |r| r.get(0),
            )?;
            if !busy {
                self.insert_job("agent_renew", &tenant, &json!({"agent_id": id, "auto": true}))?;
            }
        }
        Ok(())
    }

    /// `agent-cert`, `renew-issued` and `renewed` lines of a job naming `expected`
    /// (renewal lines only from `agent_renew` jobs); `None` = group backups, where
    /// each line must name an agent of the job's tenant.
    pub(crate) fn agent_cert_lines(&self, job: &Job, log: &str, expected: Option<&str>) -> Result<()> {
        for l in log.lines() {
            let Some((kind, v)) = ["agent-cert ", "renew-issued ", "renewed "].iter().find_map(|p| {
                let v = serde_json::from_str::<Value>(l.strip_prefix(p)?).ok()?;
                Some((p.trim_end(), v))
            }) else {
                continue;
            };
            let (Some(id), Some(fp)) = (v["agent_id"].as_str().filter(|a| valid_agent_id(a)), fingerprint(&v)) else {
                continue;
            };
            if expected.is_some_and(|e| e != id) || (kind != "agent-cert" && job.kind != "agent_renew") {
                continue;
            }
            let (nb, na) = (v["not_before"].as_i64(), v["not_after"].as_i64());
            let c = self.db.conn();
            match kind {
                // the presented certificate: validity, and confirmation of a renewed one
                "agent-cert" => {
                    c.execute(
                        "UPDATE agents SET cert_sha256 = ?2, cert_sha256_next = NULL, cert_issued = ?3, cert_expires = ?4 \
                         WHERE id = ?1 AND tenant = ?5 AND (cert_sha256 = ?2 OR cert_sha256_next = ?2)",
                        params![id, fp, nb, na, job.tenant],
                    )?;
                }
                "renew-issued" => {
                    c.execute(
                        "UPDATE agents SET cert_sha256_next = ?2 WHERE id = ?1 AND tenant = ?3 AND cert_sha256 IS NOT NULL",
                        params![id, fp, job.tenant],
                    )?;
                }
                _ => {
                    let n = c.execute(
                        "UPDATE agents SET cert_sha256 = ?2, cert_sha256_next = NULL, cert_issued = ?3, cert_expires = ?4 \
                         WHERE id = ?1 AND tenant = ?5 AND (cert_sha256_next = ?2 OR cert_sha256 = ?2)",
                        params![id, fp, nb, na, job.tenant],
                    )?;
                    drop(c);
                    if n == 1 {
                        self.db.audit(
                            ACTOR,
                            "agent.cert_renewed",
                            &format!("agent/{id}"),
                            &json!({"job": job.id, "cert_sha256": fp, "not_after": na, "auto": job.params["auto"] == true}),
                        )?;
                        self.resolve(&format!("cert_expiry:agent:{id}"))?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_timing() {
        let now = 1_000_000_000;
        // 10-year certificate: renewed during its last year
        let issued = now - 9 * 365 * DAY;
        assert!(!renewal_due(Some(issued), issued + 3650 * DAY, now - 300 * DAY));
        assert!(renewal_due(Some(issued), issued + 3650 * DAY, now + 10 * DAY));
        // one-year certificate: 10 % = 36 days > 30 days
        assert!(renewal_due(Some(now - 330 * DAY), now + 35 * DAY, now));
        assert!(!renewal_due(Some(now - 300 * DAY), now + 65 * DAY, now));
        // unknown issue date: 30 days only
        assert!(!renewal_due(None, now + 31 * DAY, now));
        assert!(renewal_due(None, now + 29 * DAY, now));
        assert!(renewal_due(None, now - DAY, now), "expired");
    }
}
