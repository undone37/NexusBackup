// Minimal Node globals used by vite.config.ts and the mock (avoids pulling in @types/node).
declare const process: { env: Record<string, string | undefined> };
