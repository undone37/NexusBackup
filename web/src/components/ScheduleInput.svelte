<script lang="ts">
  // Schedule builder (Phase 13b): kind + fields, kept in sync with the schedule string the API takes.
  import { t } from '../lib/i18n';
  import { DAYS, EVERY, EVERY_MIN, formatSchedule, parseSchedule, type SchedForm } from '../lib/schedule';

  type Kind = 'daily' | 'minutes' | 'hours' | 'weekdays' | 'monthly';
  // `kinds`: the forms offered (scheduled reports: no hourly schedules)
  let {
    value = $bindable(''),
    id,
    kinds = ['daily', 'minutes', 'hours', 'weekdays', 'monthly'],
    hint = t.policies.scheduleHint,
  }: { value?: string; id: string; kinds?: Kind[]; hint?: string } = $props();
  let f: SchedForm = $state(parseSchedule(value) ?? parseSchedule('daily 01:00')!);
  // An outside change of the string (another policy opened) resets the form.
  let last = value;
  $effect(() => {
    if (value !== last) {
      const p = parseSchedule(value);
      if (p) f = p;
      last = value;
    }
  });
  function sync() {
    if (f.kind === 'weekdays' && !f.days.length) return;
    // switching between hours and minutes: keep `every` valid for the new kind
    if (f.kind === 'minutes' && !EVERY_MIN.includes(f.every)) f.every = 15;
    if (f.kind === 'hours' && !EVERY.includes(f.every)) f.every = 1;
    value = last = formatSchedule(f);
  }
  const time = (h: number, m: number) => `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
  function setTime(e: Event) {
    const [h, m] = (e.currentTarget as HTMLInputElement).value.split(':').map(Number);
    if (Number.isInteger(h) && Number.isInteger(m)) {
      f.hour = h;
      f.minute = m;
      sync();
    }
  }
</script>

<div class="sched" role="group" aria-labelledby="{id}-label">
  <div class="form-grid">
    <div class="field">
      <label for="{id}-kind">{t.runctl.kind}</label>
      <select id="{id}-kind" bind:value={f.kind} onchange={sync}>
        {#each kinds as k (k)}<option value={k}>{t.runctl.kinds[k]}</option>{/each}
      </select>
    </div>
    {#if f.kind === 'minutes'}
      <div class="field">
        <label for="{id}-everym">{t.runctl.every}</label>
        <select id="{id}-everym" bind:value={f.every} onchange={sync} aria-describedby="{id}-everym-hint">
          {#each EVERY_MIN as n (n)}<option value={n}>{t.runctl.minutesN(n)}</option>{/each}
        </select>
        <div class="hint" id="{id}-everym-hint">{t.runctl.minutesHint}</div>
      </div>
    {:else if f.kind === 'hours'}
      <div class="field">
        <label for="{id}-every">{t.runctl.every}</label>
        <select id="{id}-every" bind:value={f.every} onchange={sync}>
          {#each EVERY as n (n)}<option value={n}>{t.runctl.hoursN(n)}</option>{/each}
        </select>
      </div>
      <div class="field">
        <label for="{id}-min">{t.runctl.minute}</label>
        <input id="{id}-min" type="number" min="0" max="59" bind:value={f.minute} oninput={sync} />
      </div>
    {:else}
      {#if f.kind === 'monthly'}
        <div class="field">
          <label for="{id}-mday">{t.runctl.monthDay}</label>
          <input id="{id}-mday" type="number" min="1" max="31" bind:value={f.monthDay} oninput={sync} aria-describedby="{id}-mday-hint" />
          <div class="hint" id="{id}-mday-hint">{t.runctl.monthDayHint}</div>
        </div>
      {/if}
      <div class="field">
        <label for="{id}-at">{t.runctl.at}</label>
        <input id="{id}-at" type="time" value={time(f.hour, f.minute)} onchange={setTime} required />
      </div>
    {/if}
  </div>
  {#if f.kind === 'weekdays'}
    <fieldset class="days">
      <legend>{t.runctl.days}</legend>
      {#each DAYS as d (d)}
        <label class="inline-check"><input type="checkbox" value={d} bind:group={f.days} onchange={sync} />{d}</label>
      {/each}
    </fieldset>
  {/if}
  <div class="field">
    <label for={id} id="{id}-label">{t.runctl.raw}</label>
    <input {id} class="mono" bind:value required aria-describedby="{id}-hint" />
    <div class="hint" id="{id}-hint">{hint}</div>
  </div>
</div>

<style>
  .days {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem 1rem;
  }
</style>
