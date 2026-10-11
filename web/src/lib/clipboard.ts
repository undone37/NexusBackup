import { notify } from './notify.svelte';
import { t } from './i18n';

/** Copies text and confirms with a toast; without clipboard access (non-secure context) the text stays selectable. */
export async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    notify('ok', t.users.copied);
  } catch {
    /* clipboard unavailable */
  }
}
