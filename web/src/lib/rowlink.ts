import { href, navigate } from './router.svelte';

/** A click that belongs to a control inside the row (or selects text), not to the row. */
const ownClick = (e: Event) =>
  !!(e.target as HTMLElement | null)?.closest('a,button,input,select,textarea,label,summary,details,[role="button"]') ||
  (window.getSelection()?.toString() ?? '') !== '';

/**
 * Runs `action` when a table row is clicked anywhere outside its own links,
 * buttons and form controls (and not while selecting text): the row's main
 * action (open, edit). The control in the row stays the keyboard and
 * screen-reader way in.
 */
export function rowClick(node: HTMLElement, action: (() => void) | null) {
  let run = action;
  const click = (e: MouseEvent) => {
    if (run && e.button === 0 && !ownClick(e)) run();
  };
  // null: the row has no action for this account (no pointer, no click)
  node.classList.toggle('rowlink', !!run);
  node.addEventListener('click', click);
  return {
    update(a: (() => void) | null) {
      run = a;
      node.classList.toggle('rowlink', !!run);
    },
    destroy() {
      node.removeEventListener('click', click);
    },
  };
}

/**
 * Makes a table row open `path` when clicked anywhere on it (see [`rowClick`]);
 * Ctrl/Cmd/middle click open it in a new tab.
 */
export function rowLink(node: HTMLElement, path: string) {
  let target = path;
  const open = (e: MouseEvent) => {
    if (ownClick(e)) return;
    if (e.ctrlKey || e.metaKey || e.button === 1) window.open(href(target), '_blank', 'noopener');
    else if (e.button === 0) navigate(target);
  };
  node.classList.add('rowlink');
  node.addEventListener('click', open);
  node.addEventListener('auxclick', open);
  return {
    update(p: string) {
      target = p;
    },
    destroy() {
      node.removeEventListener('click', open);
      node.removeEventListener('auxclick', open);
    },
  };
}
