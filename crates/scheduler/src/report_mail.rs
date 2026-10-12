//! Scheduled reports (Phase 14e, docs/control-plane.md "Reports"): each report of
//! the setting `reports` is queued as an appliance job `report_send {name, from,
//! to}` when a slot of its schedule passed (the range is the previous slot up to
//! this one; "Send now" in the web UI queues one period up to now). The job
//! composes the HTML summary with one CSV per type (crate `reports`) and mails
//! it through the SMTP server of the setting `alerts`, which is already in the
//! outbound allow-list (`firewall::alert_targets`). Sent → audit `report.sent`;
//! not sent → alert `report:<name>` (resolved by the next successful send).

use crate::{alerts, Job, Scheduler, ACTOR};
use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::message::{Attachment, MultiPart};
use lettre::Message;
use serde_json::{json, Value};

pub(crate) fn alert_key(name: &str) -> String {
    format!("report:{name}")
}

/// The mail of a composed report (HTML + plain text, CSV attachments).
pub fn message(from: &str, to: &[String], m: &reports::Mail) -> Result<Message> {
    let mut b = Message::builder().from(from.parse()?).subject(m.subject.clone());
    for t in to {
        b = b.to(t.parse().with_context(|| format!("recipient {t:?}"))?);
    }
    let mut body = MultiPart::mixed().multipart(MultiPart::alternative_plain_html(m.text.clone(), m.html.clone()));
    let csv = ContentType::parse("text/csv; charset=utf-8")?;
    for (name, data) in &m.attachments {
        body = body.singlepart(Attachment::new(name.clone()).body(data.clone(), csv.clone()));
    }
    Ok(b.multipart(body)?)
}

impl Scheduler {
    /// Queues `report_send` for every scheduled report whose slot passed.
    pub(crate) fn queue_reports(&mut self, now: i64) -> Result<()> {
        let list = reports::load_scheduled(&self.db.conn())?;
        for r in list {
            let sched = match r.schedule() {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("scheduled report {}: {e:#}", r.name);
                    self.raise("warning", "report", &alert_key(&r.name), &msg, None)?;
                    continue;
                }
            };
            let busy: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind = 'report_send' AND state IN ('queued', 'running') \
                 AND json_extract(params, '$.name') = ?1",
                [&r.name],
                |row| row.get(0),
            )?;
            if busy > 0 {
                continue;
            }
            let last = self.last_run(
                &format!("report/{}", r.name),
                "SELECT MAX(created) FROM jobs WHERE kind = 'report_send' AND requested_by = 'scheduler' \
                 AND json_extract(params, '$.name') = ?1",
                &[&r.name],
                now,
            )?;
            if sched.due(last, now) {
                let (from, to) = r.range_at(sched.last_slot(now))?;
                self.insert_job("report_send", "-", &json!({"name": r.name, "from": from, "to": to}))?;
            }
        }
        Ok(())
    }

    /// Composes the report now (catalog access on the scheduler thread); the
    /// returned step only sends it. Its stdout (the job result) summarises it.
    pub(crate) fn report_step(&self, job: &Job) -> Box<dyn Fn() -> Result<String, String> + Send> {
        let prepared = self.prepare_report(job).map_err(|e| format!("{e:#}"));
        Box::new(move || {
            let (smtp, msg, summary) = prepared.as_ref().map_err(Clone::clone)?;
            alerts::send_message(smtp, msg).map_err(|e| format!("sending the mail failed: {e:#}"))?;
            Ok(summary.to_string())
        })
    }

    fn prepare_report(&self, job: &Job) -> Result<(alerts::Smtp, Message, Value)> {
        let p = &job.params;
        let name = p["name"].as_str().context("name missing")?;
        let (from, to) = (
            p["from"].as_i64().context("from missing")?,
            p["to"].as_i64().context("to missing")?,
        );
        let r = reports::load_scheduled(&self.db.conn())?
            .into_iter()
            .find(|r| r.name == name)
            .with_context(|| format!("no scheduled report named {name}"))?;
        let smtp = self
            .alerts_config()?
            .smtp
            .context("no SMTP server configured (Settings → Alert delivery)")?;
        let mail = reports::compose(&self.db.conn(), &r, &self.host, from, to, catalog::now())?;
        let msg = message(&smtp.from, &r.recipients, &mail)?;
        let summary = json!({
            "name": name, "types": r.types, "tenant": r.tenant, "recipients": r.recipients, "from": from, "to": to,
            "attachments": mail.attachments.iter().map(|a| &a.0).collect::<Vec<_>>(), "rows": mail.rows,
        });
        Ok((smtp, msg, summary))
    }

    /// After a `report_send` job: audit `report.sent` and resolve, or raise `report:<name>`.
    pub(crate) fn report_finished(&self, job: &Job, ok: bool, log: &str, result: Option<&Value>) -> Result<()> {
        let name = job.params["name"].as_str().unwrap_or_default();
        if ok {
            self.db.audit(
                ACTOR,
                "report.sent",
                &format!("report/{name}"),
                &json!({"job": job.id, "summary": result}),
            )?;
            return self.resolve(&alert_key(name));
        }
        let why = log
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("see the job log");
        self.raise(
            "warning",
            "report",
            &alert_key(name),
            &format!("scheduled report {name} could not be sent (job {}): {why}", job.id),
            None,
        )
    }
}
