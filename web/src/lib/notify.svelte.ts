export type NoticeKind = 'ok' | 'error' | 'pending' | 'info';
export interface Notice {
  id: number;
  kind: NoticeKind;
  text: string;
}

export const notices = $state<Notice[]>([]);
let next = 1;

export function notify(kind: NoticeKind, text: string, ttlMs = kind === 'error' || kind === 'pending' ? 12000 : 5000) {
  const id = next++;
  notices.push({ id, kind, text });
  setTimeout(() => dismiss(id), ttlMs);
}

export function dismiss(id: number) {
  const i = notices.findIndex((n) => n.id === id);
  if (i >= 0) notices.splice(i, 1);
}
