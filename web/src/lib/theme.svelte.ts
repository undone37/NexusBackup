// Light / dark theme. Default: follow the OS (`prefers-color-scheme`); the top-bar toggle pins a
// choice for this browser (localStorage). app.css reads `<html data-theme>` via `color-scheme`.

export type ThemeChoice = 'system' | 'light' | 'dark';
const KEY = 'nexus.theme';

function stored(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

const media = window.matchMedia('(prefers-color-scheme: dark)');

export const theme = $state<{ choice: ThemeChoice; dark: boolean }>({ choice: stored(), dark: false });

function apply() {
  const root = document.documentElement;
  if (theme.choice === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', theme.choice);
  theme.dark = theme.choice === 'dark' || (theme.choice === 'system' && media.matches);
}

/** Called once from main.ts before the first render (no flash of the wrong theme). */
export function initTheme() {
  apply();
  media.addEventListener('change', apply);
}

export function setTheme(choice: ThemeChoice) {
  theme.choice = choice;
  try {
    if (choice === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, choice);
  } catch {
    /* storage disabled: the choice lasts for this page view */
  }
  apply();
}

/** The toggle cycles through the three choices. */
export const nextTheme = (c: ThemeChoice): ThemeChoice => (c === 'system' ? 'light' : c === 'light' ? 'dark' : 'system');
