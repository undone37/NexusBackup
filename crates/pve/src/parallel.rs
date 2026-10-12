//! Several guests of one `backup-all` at once (group `parallel_guests`,
//! docs/pve-connector.md "Parallel guests"): up to `n` workers, each takes the
//! next guest on the node with the fewest running backups, so the load spreads
//! over the cluster (PVE may serialise vzdump runs on one node with its global
//! vzdump lock: guests of that node then simply wait for each other).

use std::collections::HashMap;
use std::sync::Mutex;

/// Index into `pending` of the next item: the first one whose node has the
/// fewest running backups.
pub fn pick(pending: &[usize], nodes: &[&str], running: &HashMap<String, usize>) -> Option<usize> {
    pending
        .iter()
        .enumerate()
        .min_by_key(|(pos, &i)| (running.get(nodes[i]).copied().unwrap_or(0), *pos))
        .map(|(pos, _)| pos)
}

/// Runs `work` for every `(item, node)` with at most `n` at once; results in
/// item order.
pub fn run<T: Sync, R: Send>(items: &[(T, String)], n: usize, work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let nodes: Vec<&str> = items.iter().map(|(_, n)| n.as_str()).collect();
    let state = Mutex::new(((0..items.len()).collect::<Vec<_>>(), HashMap::<String, usize>::new()));
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..n.clamp(1, items.len().max(1)) {
            s.spawn(|| loop {
                let i = {
                    let mut st = state.lock().unwrap();
                    let (pending, running) = &mut *st;
                    let Some(pos) = pick(pending, &nodes, running) else {
                        break;
                    };
                    let i = pending.remove(pos);
                    *running.entry(nodes[i].to_owned()).or_default() += 1;
                    i
                };
                let r = work(&items[i].0);
                let mut st = state.lock().unwrap();
                *st.1.entry(nodes[i].to_owned()).or_default() -= 1;
                results.lock().unwrap()[i] = Some(r);
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|r| r.expect("every item ran"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn picks_the_least_busy_node_in_order() {
        let nodes = ["a", "a", "b", "c"];
        let mut running = HashMap::new();
        assert_eq!(pick(&[0, 1, 2, 3], &nodes, &running), Some(0), "idle: list order");
        running.insert("a".to_string(), 1);
        assert_eq!(pick(&[1, 2, 3], &nodes, &running), Some(1), "b before the busy a");
        running.insert("b".to_string(), 1);
        running.insert("c".to_string(), 2);
        assert_eq!(pick(&[1, 3], &nodes, &running), Some(0), "a(1) before c(2)");
        assert_eq!(pick(&[], &nodes, &running), None);
    }

    #[test]
    fn runs_at_most_n_and_keeps_order() {
        let items: Vec<(u32, String)> = (0..12).map(|i| (i, format!("n{}", i % 3))).collect();
        let (now, max) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let out = run(&items, 3, |&i| {
            let c = now.fetch_add(1, Ordering::SeqCst) + 1;
            max.fetch_max(c, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            now.fetch_sub(1, Ordering::SeqCst);
            i * 2
        });
        assert_eq!(out, (0..12).map(|i| i * 2).collect::<Vec<_>>());
        assert_eq!(max.load(Ordering::SeqCst), 3);
        assert!(run(&Vec::<(u32, String)>::new(), 4, |&i| i).is_empty());
        assert_eq!(run(&items[..1], 8, |&i| i + 1), vec![1]);
    }
}
