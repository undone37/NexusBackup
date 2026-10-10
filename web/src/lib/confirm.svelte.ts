// In-page replacements for window.confirm()/prompt(): native dialogs block the page
// (and browser automation / screenshot scripts) and look foreign next to <Modal>.
export const pending = $state<{
  text: string;
  /** `null` = yes/no question, otherwise the text field's value */
  input: string | null;
  resolve: ((v: string | null) => void) | null;
}>({ text: '', input: null, resolve: null });

function ask(text: string, input: string | null): Promise<string | null> {
  pending.resolve?.(null); // a newer question replaces an unanswered one
  return new Promise((resolve) => {
    pending.text = text;
    pending.input = input;
    pending.resolve = resolve;
  });
}

/** Yes/no question; resolves `true` only on "Confirm". */
export async function askConfirm(text: string): Promise<boolean> {
  return (await ask(text, null)) !== null;
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
