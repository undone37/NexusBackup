// In-page replacements for window.confirm()/prompt(): native dialogs block the page
// (and browser automation / screenshot scripts) and look foreign next to <Modal>.
/** How a question looks: its title, the confirming button's label, red for what cannot be undone. */
export interface AskOptions {
  title?: string;
  ok?: string;
  danger?: boolean;
}

export const pending = $state<{
  text: string;
  /** `null` = yes/no question, otherwise the text field's value */
  input: string | null;
  opts: AskOptions;
  resolve: ((v: string | null) => void) | null;
}>({ text: '', input: null, opts: {}, resolve: null });

function ask(text: string, input: string | null, opts: AskOptions = {}): Promise<string | null> {
  pending.resolve?.(null); // a newer question replaces an unanswered one
  return new Promise((resolve) => {
    pending.text = text;
    pending.input = input;
    pending.opts = opts;
    pending.resolve = resolve;
  });
}

/**
 * Yes/no question; resolves `true` only on the confirming button. For a destructive action pass
 * `{ title: 'Delete policy', ok: 'Delete', danger: true }`: the button then names the action
 * (never a bare "Confirm") and is red, and Cancel has the focus, so Enter destroys nothing.
 */
export async function askConfirm(text: string, opts?: AskOptions): Promise<boolean> {
  return (await ask(text, null, opts)) !== null;
}

/** Text question; resolves the entered text, or `null` if cancelled. */
export function askText(text: string, initial = ''): Promise<string | null> {
  return ask(text, initial);
}

export function answer(ok: boolean) {
  const r = pending.resolve;
  pending.resolve = null;
  r?.(ok ? (pending.input ?? '') : null);
}
