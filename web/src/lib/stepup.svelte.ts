// Phase 29: step-up re-authentication. A request of an account marked by a risk signal answers
// 428; the api layer asks here, the dialog (StepUpDialog, mounted once in App) posts
// /auth/step-up and resolves `true` when that worked, `false` when cancelled.
export const stepUp = $state<{ reason: string; resolve: ((ok: boolean) => void) | null }>({ reason: '', resolve: null });

let waiting: Promise<boolean> | null = null;

/** Opens the dialog (one at a time: parallel 428 answers share it). */
export function askStepUp(reason: string): Promise<boolean> {
  if (waiting) return waiting;
  waiting = new Promise<boolean>((resolve) => {
    stepUp.reason = reason;
    stepUp.resolve = (ok) => {
      waiting = null;
      stepUp.resolve = null;
      resolve(ok);
    };
  });
  return waiting;
}
