export type NoticeKind = 'ok' | 'error' | 'pending' | 'info';
export interface Notice {
  id: number;
  kind: NoticeKind;
  text: string;
  /** where to follow up (e.g. the job an action started) */
  link?: { path: string; label: string };
}

export const notices = $state<Notice[]>([]);
let next = 1;

export function notify(
  kind: NoticeKind,
  text: string,
  ttlMs = kind === 'error' || kind === 'pending' ? 12000 : 5000,
  link?: { path: string; label: string },
) {
  const id = next++;
  // a notice with a link stays long enough to follow it
  if (link) ttlMs = Math.max(ttlMs, 10000);
  notices.push({ id, kind, text, link });
  setTimeout(() => dismiss(id), ttlMs);
}

export function dismiss(id: number) {
  const i = notices.findIndex((n) => n.id === id);
  if (i >= 0) notices.splice(i, 1);
}
